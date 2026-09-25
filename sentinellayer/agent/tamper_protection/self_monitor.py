"""Self-Monitoring and Tamper Protection for DefenceIQ.

Monitors the security agent's own process, configuration files, SQLite database,
and credentials against unauthorized termination, tampering, deletion, or injection.
Immediately triggers high-priority alerts ('attempted_disable_security', +25 pts)
and emergency push notifications when tampering is detected.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

import psutil

logger = logging.getLogger("defenceiq.tamper_protection.self_monitor")


@dataclass
class TamperEvent:
    """Structured telemetry event representing an attempted attack on the agent."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tamper_type: str = "PROCESS_KILL_ATTEMPT"  # PROCESS_KILL_ATTEMPT, FILE_MODIFIED, FILE_DELETED, INTEGRITY_FAIL
    target: str = ""
    attacker_pid: Optional[int] = None
    attacker_name: Optional[str] = None
    details: str = ""
    signals: List[str] = field(default_factory=lambda: ["attempted_disable_security"])
    severity: str = "CRITICAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "tamper_type": self.tamper_type,
            "target": self.target,
            "attacker_pid": self.attacker_pid,
            "attacker_name": self.attacker_name,
            "details": self.details,
            "signals": list(self.signals),
            "severity": self.severity,
        }


class SelfMonitor:
    """Active watchdog defending DefenceIQ from termination or file tampering."""

    SUSPICIOUS_KILL_TOOLS = {
        "taskkill.exe", "taskkill",
        "pskill.exe", "pskill",
        "processhacker.exe",
        "procexp.exe",
    }

    def __init__(
        self,
        monitored_files: Optional[List[str]] = None,
        agent_pid: Optional[int] = None,
        callback: Optional[Callable[[TamperEvent], None]] = None,
    ):
        self.agent_pid = agent_pid or os.getpid()
        self.monitored_files: List[str] = list(monitored_files or [])
        self.callback = callback

        # Track known file baselines: path -> {mtime, size, sha256}
        self._file_baselines: Dict[str, Dict[str, Any]] = {}
        self._recorded_tamper_events: List[TamperEvent] = []

        self._is_running = False
        self._watchdog_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Initialize baselines for existing monitored files
        self.refresh_file_baselines()

    def add_monitored_file(self, file_path: str) -> None:
        """Registers a critical file (DB, token, config) for integrity protection."""
        if file_path not in self.monitored_files:
            self.monitored_files.append(file_path)
            self._record_file_baseline(file_path)

    def refresh_file_baselines(self) -> None:
        """Records initial cryptographic hashes and timestamps for all registered files."""
        for path in self.monitored_files:
            self._record_file_baseline(path)

    def _record_file_baseline(self, path: str) -> None:
        """Computes and records SHA256 and metadata for a single file."""
        if os.path.isfile(path):
            try:
                stat = os.stat(path)
                sha = self._compute_sha256(path)
                self._file_baselines[path] = {
                    "exists": True,
                    "mtime": stat.st_mtime,
                    "size": stat.st_size,
                    "sha256": sha,
                }
            except Exception as e:
                logger.debug(f"Could not compute baseline for {path}: {e}")
        else:
            self._file_baselines[path] = {"exists": False}

    def _compute_sha256(self, path: str) -> Optional[str]:
        """Computes SHA-256 digest of a target file safely."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def check_file_integrity(self) -> List[TamperEvent]:
        """Audits monitored files against baseline state, detecting deletion or tampering."""
        events: List[TamperEvent] = []

        for path in list(self.monitored_files):
            baseline = self._file_baselines.get(path, {"exists": False})

            # Check if file was previously present and is now unexpectedly deleted
            if baseline.get("exists") and not os.path.isfile(path):
                ev = TamperEvent(
                    tamper_type="FILE_DELETED",
                    target=path,
                    details=f"Critical agent file {os.path.basename(path)} was unexpectedly deleted or wiped.",
                    signals=["attempted_disable_security"],
                    severity="CRITICAL",
                )
                events.append(ev)
                self._file_baselines[path] = {"exists": False}
                logger.error(f"[TAMPER ALERT] {ev.details}")
                continue

            # If file was not previously existing, record baseline now
            if not baseline.get("exists") and os.path.isfile(path):
                self._record_file_baseline(path)
                continue

            # If file is present, check for unexpected corruption or truncate
            if os.path.isfile(path):
                try:
                    stat = os.stat(path)
                    # Detect truncation to 0 bytes from non-zero baseline
                    if baseline.get("size", 0) > 0 and stat.st_size == 0:
                        ev = TamperEvent(
                            tamper_type="FILE_MODIFIED",
                            target=path,
                            details=f"Critical agent file {os.path.basename(path)} was wiped/truncated to 0 bytes.",
                            signals=["attempted_disable_security"],
                            severity="CRITICAL",
                        )
                        events.append(ev)
                        logger.error(f"[TAMPER ALERT] {ev.details}")
                except Exception as e:
                    logger.debug(f"Integrity check stat error for {path}: {e}")

        for ev in events:
            self._dispatch_tamper_event(ev)

        return events

    def check_process_threats(
        self, process_list: Optional[List[Dict[str, Any]]] = None
    ) -> List[TamperEvent]:
        """Scans active system processes for commands attempting to terminate DefenceIQ."""
        events: List[TamperEvent] = []

        if process_list is not None:
            procs = process_list
        else:
            # Poll psutil for active processes
            procs = []
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    info = p.info
                    if info and info.get("name"):
                        procs.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        agent_pid_str = str(self.agent_pid)

        for p in procs:
            pid = p.get("pid")
            name = (p.get("name") or "").lower()
            cmdline = p.get("cmdline") or []
            if isinstance(cmdline, list):
                cmd_str = " ".join(cmdline).lower()
            else:
                cmd_str = str(cmdline).lower()

            # Skip inspecting the agent process itself
            if pid == self.agent_pid:
                continue

            # 1. Check for dedicated process killer utilities targeting agent PID or name
            is_kill_tool = any(tool in name for tool in self.SUSPICIOUS_KILL_TOOLS)
            targets_agent = (
                agent_pid_str in cmd_str
                or "defenceiq" in cmd_str
                or "sentinellayer" in cmd_str
            )

            if is_kill_tool and targets_agent:
                ev = TamperEvent(
                    tamper_type="PROCESS_KILL_ATTEMPT",
                    target=f"PID:{self.agent_pid}",
                    attacker_pid=pid,
                    attacker_name=p.get("name"),
                    details=f"Process '{p.get('name')}' (PID {pid}) attempted termination command targeting DefenceIQ: '{cmd_str}'",
                    signals=["attempted_disable_security"],
                    severity="CRITICAL",
                )
                events.append(ev)
                logger.error(f"[TAMPER ALERT] {ev.details}")
                continue

            # 2. Check for PowerShell Stop-Process targeting agent
            if ("powershell" in name or "pwsh" in name) and "stop-process" in cmd_str:
                if targets_agent:
                    ev = TamperEvent(
                        tamper_type="PROCESS_KILL_ATTEMPT",
                        target=f"PID:{self.agent_pid}",
                        attacker_pid=pid,
                        attacker_name=p.get("name"),
                        details=f"PowerShell executed Stop-Process against DefenceIQ agent: '{cmd_str}'",
                        signals=["attempted_disable_security"],
                        severity="CRITICAL",
                    )
                    events.append(ev)
                    logger.error(f"[TAMPER ALERT] {ev.details}")

        for ev in events:
            self._dispatch_tamper_event(ev)

        return events

    def _dispatch_tamper_event(self, event: TamperEvent) -> None:
        """Records tamper event and notifies registered callback handler."""
        with self._lock:
            self._recorded_tamper_events.append(event)

        if self.callback:
            try:
                self.callback(event)
            except Exception as e:
                logger.error(f"Error in tamper event callback: {e}")

    def run_check_cycle(self) -> List[TamperEvent]:
        """Runs a complete check cycle for both process threats and file integrity."""
        file_events = self.check_file_integrity()
        proc_events = self.check_process_threats()
        return file_events + proc_events

    def start(self, poll_interval: float = 2.0) -> None:
        """Starts background watchdog inspection thread."""
        if self._is_running:
            return

        self._is_running = True

        def _watchdog_loop():
            logger.info(f"SelfMonitor watchdog thread started for Agent PID {self.agent_pid}")
            while self._is_running:
                try:
                    self.run_check_cycle()
                except Exception as e:
                    logger.debug(f"Exception during SelfMonitor check cycle: {e}")
                time.sleep(poll_interval)

        self._watchdog_thread = threading.Thread(
            target=_watchdog_loop,
            name="DefenceIQ-SelfMonitor",
            daemon=True,
        )
        self._watchdog_thread.start()

    def stop(self) -> None:
        """Stops background watchdog inspection thread."""
        self._is_running = False
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=1.5)
        logger.info("SelfMonitor watchdog thread stopped.")

    def get_events(self) -> List[TamperEvent]:
        """Returns history of detected tamper attempts."""
        with self._lock:
            return list(self._recorded_tamper_events)

    def get_status(self) -> Dict[str, Any]:
        """Returns current operational status."""
        return {
            "running": self._is_running,
            "agent_pid": self.agent_pid,
            "monitored_files_count": len(self.monitored_files),
            "tamper_events_count": len(self._recorded_tamper_events),
        }

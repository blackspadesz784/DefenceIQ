"""DefenceIQ - Event Correlator.

Chains related process, file, and network events across a sliding temporal
window per process tree. Combines multi-source telemetry signals and computes
updated incident risk scores with full explainability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from sentinellayer.agent.ai_engine.risk_scoring import RiskScoringEngine, ScoreResult
from sentinellayer.agent.monitors.process_monitor import ProcessEvent
from sentinellayer.agent.monitors.file_monitor import FileEvent
from sentinellayer.agent.monitors.network_monitor import NetworkEvent
from sentinellayer.agent.monitors.usb_monitor import USBEvent
from sentinellayer.agent.tamper_protection import TamperEvent

logger = logging.getLogger("DefenceIQ.EventCorrelator")


@dataclass
class Incident:
    """Consolidated security incident representing correlated multi-signal activity."""
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    root_pid: int = 0
    root_process_name: str = ""
    involved_pids: List[int] = field(default_factory=list)
    touched_files: List[str] = field(default_factory=list)
    network_destinations: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    score_result: Optional[ScoreResult] = None
    status: str = "OPEN"  # OPEN, CONTAINED, RESOLVED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "created_at": datetime.fromtimestamp(self.created_at, timezone.utc).isoformat(),
            "updated_at": datetime.fromtimestamp(self.updated_at, timezone.utc).isoformat(),
            "root_pid": self.root_pid,
            "root_process_name": self.root_process_name,
            "involved_pids": list(self.involved_pids),
            "touched_files": list(self.touched_files),
            "network_destinations": list(self.network_destinations),
            "signals": list(self.signals),
            "score": self.score_result.score if self.score_result else 0,
            "band": self.score_result.band if self.score_result else "GREEN",
            "explanation": self.score_result.explanation if self.score_result else "",
            "contributing_signals": [
                s.__dict__ for s in (self.score_result.contributing_signals if self.score_result else [])
            ],
            "status": self.status,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ProcessTreeContext:
    """Maintains state, process lineage, and accumulated telemetry signals for a process tree."""

    def __init__(self, root_pid: int, root_process_name: str):
        self.incident_id = str(uuid.uuid4())
        self.root_pid = root_pid
        self.root_process_name = root_process_name
        self.involved_pids: Set[int] = {root_pid}
        self.touched_files: Set[str] = set()
        self.network_destinations: Set[str] = set()
        self.signals: List[str] = []
        self.created_at = time.time()
        self.last_activity = time.time()
        self.current_score_result: Optional[ScoreResult] = None


class EventCorrelator:
    """Correlates cross-domain events (Process, File, Network) across a sliding time window."""

    def __init__(
        self,
        scoring_engine: Optional[RiskScoringEngine] = None,
        window_seconds: float = 60.0,
        ml_anomaly_detector: Optional[Any] = None,
    ):
        self.scoring_engine = scoring_engine or RiskScoringEngine()
        self.window_seconds = window_seconds
        self.ml_anomaly_detector = ml_anomaly_detector

        # Map pid -> ProcessTreeContext
        self._pid_to_context: Dict[int, ProcessTreeContext] = {}
        # Active incident records: incident_id -> Incident
        self._active_incidents: Dict[str, Incident] = {}
        # Callbacks invoked when an incident is created or updated
        self.incident_callbacks: List[Callable[[Incident], None]] = []

    def register_incident_callback(self, callback: Callable[[Incident], None]):
        """Registers a callback handler invoked whenever an incident is updated."""
        self.incident_callbacks.append(callback)

    def _emit_incident(self, incident: Incident):
        """Notifies registered listeners of incident updates."""
        for cb in self.incident_callbacks:
            try:
                cb(incident)
            except Exception as e:
                logger.error(f"Error in incident callback: {e}")

    def prune_stale_contexts(self):
        """Prunes inactive contexts older than window_seconds that remain in GREEN band."""
        now = time.time()
        cutoff = now - self.window_seconds

        stale_pids = []
        for pid, ctx in self._pid_to_context.items():
            if ctx.last_activity < cutoff:
                # Keep active if score is elevated above GREEN
                if ctx.current_score_result and ctx.current_score_result.band != "GREEN":
                    continue
                stale_pids.append(pid)

        for pid in stale_pids:
            self._pid_to_context.pop(pid, None)

    def _get_or_create_context(
        self, pid: int, name: str, ppid: Optional[int] = None
    ) -> ProcessTreeContext:
        """Finds existing process tree context via PID or parent PID, or creates a new one."""
        self.prune_stale_contexts()

        # 1. Direct PID match
        if pid in self._pid_to_context:
            ctx = self._pid_to_context[pid]
            ctx.last_activity = time.time()
            return ctx

        # 2. Parent-child correlation: if PPID is tracked, join the parent's tree
        if ppid and ppid in self._pid_to_context:
            parent_ctx = self._pid_to_context[ppid]
            parent_ctx.involved_pids.add(pid)
            parent_ctx.last_activity = time.time()
            self._pid_to_context[pid] = parent_ctx
            return parent_ctx

        # 3. New independent process tree context
        new_ctx = ProcessTreeContext(root_pid=pid, root_process_name=name)
        self._pid_to_context[pid] = new_ctx
        return new_ctx

    def process_event(self, event: Any) -> Optional[Incident]:
        """Routes any structured telemetry event into the correlator and updates scoring."""
        if isinstance(event, ProcessEvent):
            return self.correlate_process_event(event)
        elif isinstance(event, FileEvent):
            return self.correlate_file_event(event)
        elif isinstance(event, NetworkEvent):
            return self.correlate_network_event(event)
        elif isinstance(event, USBEvent):
            return self.correlate_usb_event(event)
        elif isinstance(event, TamperEvent):
            return self.correlate_tamper_event(event)
        return None

    def correlate_tamper_event(self, event: TamperEvent) -> Incident:
        """Processes a TamperEvent (agent defense evasion/tampering) and updates scoring."""
        attacker_pid = event.attacker_pid or 0
        attacker_name = event.attacker_name or "TamperActor"
        ctx = self._get_or_create_context(pid=attacker_pid, name=attacker_name)
        ctx.last_activity = time.time()
        if event.target and event.target not in ctx.touched_files:
            ctx.touched_files.add(event.target)

        for sig in event.signals:
            if sig not in ctx.signals:
                ctx.signals.append(sig)

        return self._evaluate_and_update_incident(ctx)

    def correlate_usb_event(self, event: USBEvent) -> Optional[Incident]:
        """Processes a USBEvent, creates or updates a removable media context, and scores threat."""
        # Benign insertion/removal with no risk signals does not elevate an incident
        has_threats = any(
            s in event.signals
            for s in ("created_persistence_autorun", "usb_autorun_detected", "usb_executable_present", "known_malicious_hash", "yara_rule_matched")
        )
        if not has_threats:
            return None

        # Dedicated context for removable device (PID 0)
        ctx = self._get_or_create_context(pid=0, name=f"USB:{event.volume_name or event.drive_path or 'Drive'}")
        ctx.last_activity = time.time()

        for f in event.metadata.get("executables", []):
            if isinstance(f, dict) and "path" in f:
                ctx.touched_files.add(f["path"])
        if "autorun" in event.metadata and "path" in event.metadata["autorun"]:
            ctx.touched_files.add(event.metadata["autorun"]["path"])

        for sig in event.signals:
            if sig not in ctx.signals:
                ctx.signals.append(sig)

        return self._evaluate_and_update_incident(ctx)

    def correlate_process_event(self, event: ProcessEvent) -> Incident:
        """Processes a ProcessEvent, updates process tree lineage, and re-evaluates risk score."""
        ctx = self._get_or_create_context(event.pid, event.name, event.ppid)
        ctx.last_activity = time.time()

        for sig in event.signals:
            if sig not in ctx.signals:
                ctx.signals.append(sig)

        # Auxiliary ML Anomaly Detection Evaluation
        if self.ml_anomaly_detector:
            try:
                proc_info = {
                    "name": event.name,
                    "pid": event.pid,
                    "cpu_percent": getattr(event, "cpu_percent", 0.0),
                    "memory_rss_mb": getattr(event, "memory_mb", getattr(event, "memory_rss_mb", 0.0)),
                    "child_count": max(0, len(ctx.involved_pids) - 1),
                }
                net_info = {"open_connections": len(ctx.network_destinations)}
                file_info = {"file_write_burst": len(ctx.touched_files), "entropy_delta": 0.0}
                ml_res = self.ml_anomaly_detector.evaluate_telemetry(proc_info, net_info, file_info)
                if ml_res and ml_res.get("signal") and ml_res["signal"] not in ctx.signals:
                    ctx.signals.append(ml_res["signal"])
            except Exception as e:
                logger.debug(f"ML evaluation error in correlator: {e}")

        return self._evaluate_and_update_incident(ctx)

    def correlate_file_event(self, event: FileEvent) -> Optional[Incident]:
        """Processes a FileEvent and attaches file indicators to active contexts."""
        # Attribute to active contexts if applicable, or most active recent context
        target_ctx = None
        if self._pid_to_context:
            # Find the most recently active context
            target_ctx = max(self._pid_to_context.values(), key=lambda c: c.last_activity)
            target_ctx.touched_files.add(event.file_path)
            target_ctx.last_activity = time.time()

            for sig in event.signals:
                if sig not in target_ctx.signals:
                    target_ctx.signals.append(sig)

            return self._evaluate_and_update_incident(target_ctx)
        return None

    def correlate_network_event(self, event: NetworkEvent) -> Optional[Incident]:
        """Processes a NetworkEvent and attaches network indicators to the originating PID context."""
        if not event.pid:
            return None

        ctx = self._get_or_create_context(event.pid, event.process_name or "unknown")
        ctx.last_activity = time.time()
        if event.remote_address:
            ctx.network_destinations.add(event.remote_address)

        for sig in event.signals:
            if sig not in ctx.signals:
                ctx.signals.append(sig)

        return self._evaluate_and_update_incident(ctx)

    def _evaluate_and_update_incident(self, ctx: ProcessTreeContext) -> Incident:
        """Computes current risk score, generates Incident snapshot, and invokes callbacks."""
        score_res = self.scoring_engine.calculate_score(ctx.signals)
        ctx.current_score_result = score_res

        incident = Incident(
            incident_id=ctx.incident_id,
            created_at=ctx.created_at,
            updated_at=time.time(),
            root_pid=ctx.root_pid,
            root_process_name=ctx.root_process_name,
            involved_pids=list(ctx.involved_pids),
            touched_files=list(ctx.touched_files),
            network_destinations=list(ctx.network_destinations),
            signals=list(ctx.signals),
            score_result=score_res,
            status="OPEN",
        )

        self._active_incidents[ctx.incident_id] = incident
        self._emit_incident(incident)
        return incident

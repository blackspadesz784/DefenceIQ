"""DefenceIQ - USB & Removable Storage Monitor (Milestone 2 - Phase 11).

Monitors hardware device insertion events, scans newly mounted removable storage
volumes for autorun configurations, suspicious executables, and dropped payloads.
"""

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
import platform
import shutil
import sys
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

import psutil

from sentinellayer.agent.config.settings import USBMonitorConfig, default_settings
from sentinellayer.agent.detection.reputation_engine import ReputationEngine
from sentinellayer.agent.detection.static_analysis import StaticAnalyzer
from sentinellayer.agent.detection.yara_engine import YaraEngine

logger = logging.getLogger("DefenceIQ.USBMonitor")

# Windows API constants
DRIVE_REMOVABLE = 2
DRIVE_CDROM = 5


@dataclass
class USBEvent:
    """Event emitted when a USB/removable drive is connected or activity is detected."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "DEVICE_INSERTED"  # DEVICE_INSERTED, DEVICE_REMOVED, AUTORUN_DETECTED, EXECUTABLE_FOUND, FILE_COPIED
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    drive_path: str = ""
    volume_name: str = ""
    device_id: str = ""
    signals: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class USBMonitor:
    """Detects removable drive insertion, autorun configurations, and scans executables."""

    def __init__(
        self,
        event_bus: Optional[asyncio.Queue] = None,
        config: Optional[USBMonitorConfig] = None,
        static_analyzer: Optional[StaticAnalyzer] = None,
        yara_engine: Optional[YaraEngine] = None,
        reputation_engine: Optional[ReputationEngine] = None,
    ):
        self.event_bus = event_bus
        self.config = config or default_settings.usb_monitor
        self.static_analyzer = static_analyzer
        self.yara_engine = yara_engine
        self.reputation_engine = reputation_engine

        self.active_drives: Set[str] = set()
        self.callbacks: List[Callable[[USBEvent], None]] = []
        self._running = False
        self._is_windows = platform.system().lower() == "windows"

    def register_callback(self, callback: Callable[[USBEvent], None]):
        """Registers an event callback function."""
        self.callbacks.append(callback)

    def _emit(self, event: USBEvent):
        """Dispatches an event to registered callbacks and the event bus."""
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Error in USB monitor callback: {e}")

        if self.event_bus is not None:
            try:
                self.event_bus.put_nowait(event)
            except Exception as e:
                logger.error(f"Error placing USBEvent on bus: {e}")

    def get_removable_drives(self) -> Dict[str, Dict[str, Any]]:
        """Identifies currently mounted removable storage drives."""
        removable = {}

        if self._is_windows:
            import ctypes
            kernel32 = ctypes.windll.kernel32

            for partition in psutil.disk_partitions(all=True):
                drive = partition.mountpoint
                if not drive:
                    continue

                # Standardize Windows drive root format: "E:\\"
                if not drive.endswith("\\"):
                    drive_root = drive + "\\"
                else:
                    drive_root = drive

                drive_type = kernel32.GetDriveTypeW(drive_root)
                is_removable = (drive_type == DRIVE_REMOVABLE) or ("removable" in partition.opts.lower())

                if is_removable:
                    removable[drive_root] = {
                        "device": partition.device,
                        "mountpoint": drive_root,
                        "fstype": partition.fstype,
                        "opts": partition.opts,
                        "drive_type": drive_type,
                    }
        else:
            # Fallback for Linux / macOS test environments
            for partition in psutil.disk_partitions(all=False):
                opts = partition.opts.lower()
                mount = partition.mountpoint.lower()
                if "removable" in opts or "/media" in mount or "/mnt" in mount or "/volumes" in mount:
                    removable[partition.mountpoint] = {
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "opts": partition.opts,
                        "drive_type": DRIVE_REMOVABLE,
                    }

        return removable

    def check_autorun(self, drive_path: str) -> Optional[Dict[str, Any]]:
        """Parses autorun.inf on removable drives to identify persistence/auto-execution."""
        autorun_path = os.path.join(drive_path, "autorun.inf")
        if not os.path.isfile(autorun_path):
            return None

        result = {
            "path": autorun_path,
            "target_executable": None,
            "raw_content": "",
        }

        try:
            with open(autorun_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            result["raw_content"] = content[:500]
            for line in content.splitlines():
                clean = line.strip()
                lower = clean.lower()
                if lower.startswith("open=") or lower.startswith("shellexecute="):
                    target = clean.split("=", 1)[1].strip()
                    result["target_executable"] = target
                    break
        except Exception as e:
            logger.debug(f"Could not read autorun.inf: {e}")

        return result

    def scan_drive_executables(self, drive_path: str, max_depth: int = 2) -> List[Dict[str, Any]]:
        """Scans root and shallow folders of removable drive for executable files."""
        found_executables = []
        allowed_exts = set(ext.lower() for ext in self.config.executable_extensions)

        try:
            for root, dirs, files in os.walk(drive_path):
                # Calculate depth
                rel = os.path.relpath(root, drive_path)
                depth = 0 if rel == "." else len(rel.split(os.sep))
                if depth > max_depth:
                    dirs.clear()
                    continue

                for file in files:
                    _, ext = os.path.splitext(file)
                    if ext.lower() in allowed_exts:
                        full_path = os.path.join(root, file)
                        entry: Dict[str, Any] = {
                            "path": full_path,
                            "filename": file,
                            "extension": ext.lower(),
                            "signals": [],
                        }

                        # Run layered detection engines if available
                        if self.reputation_engine:
                            rep = self.reputation_engine.check_file(full_path)
                            if rep.get("verdict") == "MALICIOUS":
                                entry["signals"].append("known_malicious_hash")

                        if self.yara_engine:
                            yara_res = self.yara_engine.scan_file(full_path)
                            if yara_res.get("has_matches"):
                                entry["signals"].append("yara_rule_matched")
                                entry["yara_rules"] = [r["rule"] for r in yara_res.get("matched_rules", [])]

                        if self.static_analyzer:
                            static_res = self.static_analyzer.analyze_file(full_path)
                            entry["signals"].extend(static_res.get("signals", []))

                        found_executables.append(entry)
        except Exception as e:
            logger.debug(f"Error scanning drive executables: {e}")

        return found_executables

    def inspect_drive(self, drive_path: str) -> USBEvent:
        """Thoroughly analyzes a connected removable drive and builds a USBEvent."""
        signals = ["usb_device_inserted"]
        metadata: Dict[str, Any] = {"drive_path": drive_path}

        # 1. Check for autorun attempt
        autorun_info = self.check_autorun(drive_path)
        if autorun_info:
            signals.append("created_persistence_autorun")
            signals.append("usb_autorun_detected")
            metadata["autorun"] = autorun_info

        # 2. Check for executables
        executables = self.scan_drive_executables(drive_path)
        if executables:
            signals.append("usb_executable_present")
            metadata["executables"] = executables
            for item in executables:
                for sig in item.get("signals", []):
                    if sig not in signals:
                        signals.append(sig)

        event_type = "AUTORUN_DETECTED" if "usb_autorun_detected" in signals else (
            "EXECUTABLE_FOUND" if "usb_executable_present" in signals else "DEVICE_INSERTED"
        )

        return USBEvent(
            event_type=event_type,
            drive_path=drive_path,
            volume_name=os.path.basename(drive_path.rstrip("\\/")),
            device_id=drive_path,
            signals=signals,
            metadata=metadata,
        )

    async def start(self):
        """Asynchronously monitors for USB device insertions and removals."""
        self._running = True
        logger.info(f"USB device monitor started. Poll interval: {self.config.poll_interval_seconds}s")

        # Initial baseline
        current_drives = self.get_removable_drives()
        self.active_drives = set(current_drives.keys())
        logger.info(f"USB baseline established. Active removable drives: {list(self.active_drives)}")

        try:
            while self._running:
                await asyncio.sleep(self.config.poll_interval_seconds)
                latest_drives = self.get_removable_drives()
                latest_keys = set(latest_drives.keys())

                # Detect newly inserted drives
                inserted = latest_keys - self.active_drives
                for drive in inserted:
                    logger.warning(f"[USB:INSERTION] Removable storage detected: {drive}")
                    event = self.inspect_drive(drive)
                    self._emit(event)

                # Detect removed drives
                removed = self.active_drives - latest_keys
                for drive in removed:
                    logger.info(f"[USB:REMOVAL] Removable storage disconnected: {drive}")
                    rem_event = USBEvent(
                        event_type="DEVICE_REMOVED",
                        drive_path=drive,
                        device_id=drive,
                        signals=["usb_device_removed"],
                    )
                    self._emit(rem_event)

                self.active_drives = latest_keys
        except asyncio.CancelledError:
            logger.info("USB monitor loop cancelled")
        finally:
            self._running = False
            logger.info("USB monitor stopped.")

    def stop(self):
        """Stops the monitoring loop."""
        self._running = False

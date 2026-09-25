"""DefenceIQ - File System Monitoring Service.

Tracks new .exe/.dll files, rapid sequential modifications, mass deletions,
mass encryption-like changes (entropy jump across many files), and changes
in sensitive system folders using watchdog. Emits structured events.
"""

import asyncio
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import math
import os
import sys
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
import uuid

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from sentinellayer.agent.config.settings import FileMonitorConfig, default_settings

logger = logging.getLogger("DefenceIQ.FileMonitor")


# ============================================================================
# Shannon Entropy Calculation
# ============================================================================
def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte string (range 0.0 to 8.0).

    Plain text is typically 3.5 - 5.0. Compressed or encrypted data is > 7.2.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def get_file_entropy(file_path: str, max_bytes: int = 65536) -> Optional[float]:
    """Reads sample bytes from a file and returns its Shannon entropy.

    Returns None if the file is inaccessible or cannot be opened.
    """
    if not os.path.isfile(file_path):
        return None
    try:
        with open(file_path, "rb") as f:
            sample = f.read(max_bytes)
            if not sample:
                return 0.0
            return calculate_entropy(sample)
    except (PermissionError, OSError):
        # File might be locked by the creating process; try one brief retry
        try:
            time.sleep(0.05)
            with open(file_path, "rb") as f:
                sample = f.read(max_bytes)
                if not sample:
                    return 0.0
                return calculate_entropy(sample)
        except Exception:
            return None


# ============================================================================
# Structured File Event Schema
# ============================================================================
@dataclass
class FileEvent:
    """Structured telemetry event emitted for file system activity."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = "FILE_CREATED"  # FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_MOVED
    file_path: str = ""
    file_name: str = ""
    extension: str = ""
    file_size_bytes: int = 0
    entropy: Optional[float] = None
    is_executable: bool = False
    is_sensitive_location: bool = False
    responsible_process: Optional[str] = None
    signals: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to standard dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize event to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Rolling Window Rate & Behavioral Analysis
# ============================================================================
class RollingWindowTracker:
    """Tracks sliding window statistics for rapid modifications, mass deletions,

    and encryption bursts (high entropy). Thread-safe.
    """

    def __init__(self, window_seconds: float = 5.0, entropy_threshold: float = 7.2):
        self.window_seconds = window_seconds
        self.entropy_threshold = entropy_threshold
        # Stores (timestamp, event_type, path, entropy)
        self._history: Deque[Tuple[float, str, str, Optional[float]]] = deque()
        self._lock = threading.Lock()

    def record_event(
        self, event_type: str, path: str, entropy: Optional[float] = None
    ) -> Tuple[int, int, int]:
        """Records an event and returns counts within the current sliding window:

        (total_modifications, total_deletions, high_entropy_modifications)
        """
        now = time.time()
        with self._lock:
            self._history.append((now, event_type, path, entropy))
            # Prune events older than window_seconds
            cutoff = now - self.window_seconds
            while self._history and self._history[0][0] < cutoff:
                self._history.popleft()

            mod_count = sum(
                1 for _, etype, _, _ in self._history if etype in ("FILE_CREATED", "FILE_MODIFIED")
            )
            del_count = sum(1 for _, etype, _, _ in self._history if etype == "FILE_DELETED")
            high_entropy_count = sum(
                1
                for _, etype, _, ent in self._history
                if etype in ("FILE_CREATED", "FILE_MODIFIED")
                and ent is not None
                and ent >= self.entropy_threshold
            )
            return mod_count, del_count, high_entropy_count


# ============================================================================
# Watchdog Event Handler
# ============================================================================
class DefenceIQFileSystemEventHandler(FileSystemEventHandler):
    """Internal event handler that translates Watchdog events into DefenceIQ FileEvents."""

    def __init__(self, monitor: "FileMonitor"):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent):
        ev_type = "FOLDER_CREATED" if event.is_directory else "FILE_CREATED"
        self.monitor.process_file_change(ev_type, event.src_path, is_directory=event.is_directory)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.monitor.process_file_change("FILE_MODIFIED", event.src_path, is_directory=False)

    def on_deleted(self, event: FileSystemEvent):
        ev_type = "FOLDER_DELETED" if event.is_directory else "FILE_DELETED"
        self.monitor.process_file_change(ev_type, event.src_path, is_directory=event.is_directory)

    def on_moved(self, event: FileSystemEvent):
        dest_path = getattr(event, "dest_path", event.src_path)
        ev_type = "FOLDER_MOVED" if event.is_directory else "FILE_MOVED"
        self.monitor.process_file_change(ev_type, dest_path, src_path=event.src_path, is_directory=event.is_directory)


# ============================================================================
# File System Monitor
# ============================================================================
class FileMonitor:
    """Continuously monitors filesystem activity using watchdog, calculates entropy,

    detects rapid modifications, mass deletions, mass encryption bursts, and sensitive folder changes.
    """

    def __init__(
        self,
        event_bus: Optional[asyncio.Queue] = None,
        config: Optional[FileMonitorConfig] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        static_analyzer: Optional[Any] = None,
        yara_engine: Optional[Any] = None,
        reputation_engine: Optional[Any] = None,
        window_monitor: Optional[Any] = None,
    ):
        self.event_bus = event_bus
        self.config = config or default_settings.file_monitor
        self.loop = loop
        self.static_analyzer = static_analyzer
        self.yara_engine = yara_engine
        self.reputation_engine = reputation_engine
        self.window_monitor = window_monitor
        self.callbacks: List[Callable[[FileEvent], None]] = []
        self._observer: Optional[Observer] = None
        self._running = False
        self._handler = DefenceIQFileSystemEventHandler(self)
        self.tracker = RollingWindowTracker(
            window_seconds=self.config.window_seconds,
            entropy_threshold=self.config.entropy_threshold,
        )
        self._recent_activities: List[Dict[str, Any]] = []
        self._recent_lock = threading.Lock()

        # Precompute lowercased sets for fast matching
        self._exec_extensions = {ext.lower() for ext in self.config.executable_extensions}
        self._sensitive_paths = [
            os.path.normcase(os.path.abspath(os.path.expandvars(p)))
            for p in self.config.sensitive_paths
        ]

    def register_callback(self, callback: Callable[[FileEvent], None]):
        """Register a callback handler for emitted file events."""
        self.callbacks.append(callback)

    def is_sensitive_path(self, path: str) -> bool:
        """Determines if a given path resides inside a sensitive system directory."""
        norm_path = os.path.normcase(os.path.abspath(path))
        for sens in self._sensitive_paths:
            if norm_path.startswith(sens):
                return True
        return False

    def emit_event(self, event: FileEvent):
        """Dispatches event to the event bus and all registered callbacks."""
        if self.event_bus is not None:
            if self.loop is not None and self.loop.is_running():
                self.loop.call_soon_threadsafe(self.event_bus.put_nowait, event)
            else:
                try:
                    self.event_bus.put_nowait(event)
                except Exception as e:
                    logger.debug(f"Event bus dispatch note: {e}")

        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in FileMonitor callback: {e}")

    def process_file_change(
        self, event_type: str, file_path: str, src_path: Optional[str] = None, is_directory: bool = False
    ) -> Optional[FileEvent]:
        """Analyzes a file change event, calculates metrics/signals, and emits a FileEvent."""
        file_name = os.path.basename(file_path)
        # Ignore agent's internal database files, locks, git objects, and development caches
        norm_fp = file_path.replace("\\", "/").lower()
        if (
            file_name.startswith("defenceiq.db")
            or file_name.endswith(".key")
            or file_name.endswith(".tmp")
            or "/.git/" in norm_fp
            or "/.gradle/" in norm_fp
            or "/.idea/" in norm_fp
            or "/__pycache__/" in norm_fp
        ):
            return None

        _, ext = os.path.splitext(file_name)
        ext_lower = ext.lower() if not is_directory else "folder"

        is_exec = ext_lower in self._exec_extensions and not is_directory
        is_sensitive = self.is_sensitive_path(file_path)

        file_size = 0
        entropy = None
        if not is_directory and "DELETED" not in event_type:
            try:
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    entropy = get_file_entropy(
                        file_path, max_bytes=self.config.max_entropy_sample_bytes
                    )
            except (OSError, PermissionError):
                pass

        # Update sliding window and check burst patterns
        mod_count, del_count, high_entropy_count = self.tracker.record_event(
            event_type, file_path, entropy
        )

        signals: List[str] = []

        # 1. New Executable / DLL
        if event_type == "FILE_CREATED" and is_exec:
            signals.append("new_executable_file")

        # 2. Sensitive folder changes
        if is_sensitive and event_type in ("FILE_CREATED", "FILE_MODIFIED", "FILE_MOVED", "FOLDER_CREATED"):
            signals.append("sensitive_folder_modification")

        # 3. Rapid sequential modifications
        if mod_count >= self.config.rapid_modification_threshold:
            signals.append("rapid_file_modifications")

        # 4. Mass encryption-like changes (high entropy burst across files)
        if high_entropy_count >= self.config.mass_encryption_threshold:
            signals.append("modified_encrypted_many_files")

        # 5. Mass deletions
        if del_count >= self.config.mass_deletion_threshold:
            signals.append("mass_file_deletions")

        # 6. Integrated Detection Engines (YARA, Static Analysis, Hash Reputation)
        detection_details: Dict[str, Any] = {}
        if not is_directory and "DELETED" not in event_type and os.path.isfile(file_path):
            if self.yara_engine:
                yara_res = self.yara_engine.scan_file(file_path)
                if yara_res.get("signals"):
                    signals.extend(yara_res["signals"])
                    detection_details["yara"] = yara_res.get("matched_rules")

            if self.static_analyzer and is_exec:
                static_res = self.static_analyzer.analyze_file(file_path)
                if static_res.get("signals"):
                    signals.extend(static_res["signals"])
                    detection_details["static_analysis"] = {
                        "mime": static_res.get("mime_type"),
                        "entropy": static_res.get("overall_entropy"),
                        "suspicious_apis": static_res.get("pe_details", {}).get("suspicious_apis_found"),
                    }

            if self.reputation_engine:
                rep_res = self.reputation_engine.check_file(file_path)
                if rep_res.get("signals"):
                    signals.extend(rep_res["signals"])
                    detection_details["reputation"] = rep_res

        # Determine responsible process from active foreground window
        responsible_proc = None
        if self.window_monitor:
            curr_act = self.window_monitor.get_current_activity()
            if curr_act:
                responsible_proc = curr_act.get("process_name")

        event = FileEvent(
            event_type=event_type,
            file_path=file_path,
            file_name=file_name,
            extension=ext_lower,
            file_size_bytes=file_size,
            entropy=entropy,
            is_executable=is_exec,
            is_sensitive_location=is_sensitive,
            responsible_process=responsible_proc,
            signals=signals,
            metadata={
                "src_path": src_path,
                "is_directory": is_directory,
                "window_mod_count": mod_count,
                "window_del_count": del_count,
                "window_high_entropy_count": high_entropy_count,
                "detection_details": detection_details,
            },
        )

        with self._recent_lock:
            self._recent_activities.insert(0, event.to_dict())
            if len(self._recent_activities) > 50:
                self._recent_activities.pop()

        self.emit_event(event)
        return event

    def get_recent_activities(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns the recent file system activities list."""
        with self._recent_lock:
            return list(self._recent_activities[:limit])

    def start(self, watch_paths: Optional[List[str]] = None):
        """Starts monitoring configured directories recursively with Watchdog."""
        if self._running:
            return

        paths_to_watch = watch_paths or self.config.watch_paths
        self._observer = Observer()
        watched_count = 0

        for raw_path in paths_to_watch:
            exp_path = os.path.abspath(os.path.expandvars(raw_path))
            if os.path.exists(exp_path) and os.path.isdir(exp_path):
                try:
                    self._observer.schedule(self._handler, exp_path, recursive=True)
                    logger.info(f"FileMonitor watching directory: {exp_path}")
                    watched_count += 1
                except Exception as e:
                    logger.warning(f"Failed to watch directory {exp_path}: {e}")
            else:
                logger.debug(f"Path does not exist, skipping: {exp_path}")

        self._observer.start()
        self._running = True
        logger.info(f"FileMonitor started with {watched_count} active directories.")

    def stop(self):
        """Stops the watchdog observer thread."""
        if self._running and self._observer:
            self._observer.stop()
            self._observer.join(timeout=2.0)
            self._running = False
            logger.info("FileMonitor stopped.")

    async def run_demo(self, watch_directory: Optional[str] = None, duration_seconds: int = 20):
        """Runs a live console demonstration of file system monitoring."""
        import tempfile

        temp_dir = watch_directory or tempfile.mkdtemp(prefix="defenceiq_filemon_")
        print("=" * 70)
        print("  DEFENCEIQ - FILE SYSTEM MONITORING DEMO (Phase 2)")
        print("=" * 70)
        print(f"Monitoring active directory: {temp_dir}")
        print(f"Duration: {duration_seconds} seconds")
        print("Creating benign files and checking entropy & signals live...")
        print("=" * 70)

        def print_event(ev: FileEvent):
            print("\n[+] FILE EVENT DETECTED:")
            print(ev.to_json(indent=2))

        self.register_callback(print_event)
        self.start(watch_paths=[temp_dir])

        try:
            # Simulate a few harmless file changes inside the test directory
            await asyncio.sleep(1.0)
            test_txt = os.path.join(temp_dir, "benign_notes.txt")
            with open(test_txt, "w") as f:
                f.write("Normal plain text file content for testing.")

            await asyncio.sleep(1.0)
            test_dll = os.path.join(temp_dir, "sample_module.dll")
            with open(test_dll, "wb") as f:
                f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

            await asyncio.sleep(duration_seconds)
        finally:
            self.stop()
            print("\n" + "=" * 70)
            print("  FILE MONITOR DEMO COMPLETE")
            print("=" * 70)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    monitor = FileMonitor()
    asyncio.run(monitor.run_demo(duration_seconds=5))

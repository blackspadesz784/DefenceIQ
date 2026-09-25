"""DefenceIQ Download Monitor.

Monitors user Downloads directory for newly downloaded files.
Extracts source domain/URL via Windows NTFS Zone.Identifier streams or active browser context.
Performs instant layered security scans (Entropy, YARA, Hash Reputation).
Strict Privacy: Never transmits actual file contents to the mobile dashboard.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("DefenceIQ.DownloadMonitor")


@dataclass
class DownloadEvent:
    """Security event generated for a newly downloaded file."""

    event_id: str = field(default_factory=lambda: hashlib.sha256(str(time.time()).encode()).hexdigest()[:12])
    file_name: str = ""
    file_type: str = ""
    source_domain: str = "Unknown"
    source_url: Optional[str] = None
    download_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    destination_path: str = ""
    file_size_bytes: int = 0
    file_size_display: str = "0 B"
    scan_verdict: str = "CLEAN"  # CLEAN, SUSPICIOUS, MALICIOUS
    risk_score: int = 0
    risk_signals: List[str] = field(default_factory=list)
    sha256: str = ""
    process_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DownloadFileSystemHandler(FileSystemEventHandler):
    """Watches Downloads directory for file creations and renames."""

    def __init__(self, monitor: "DownloadMonitor"):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.handle_file_event(event.src_path)

    def on_moved(self, event):
        # Browsers rename .crdownload/.part -> final file when download finishes
        if not event.is_directory:
            self.monitor.handle_file_event(event.dest_path)


class DownloadMonitor:
    """Monitors endpoint downloads, parses origin domains, and performs layered scans."""

    def __init__(
        self,
        downloads_dir: Optional[str] = None,
        static_analyzer: Optional[Any] = None,
        yara_engine: Optional[Any] = None,
        reputation_engine: Optional[Any] = None,
        window_monitor: Optional[Any] = None,
    ):
        self.downloads_dir = os.path.abspath(
            os.path.expandvars(downloads_dir or "%USERPROFILE%\\Downloads")
        )
        self.static_analyzer = static_analyzer
        self.yara_engine = yara_engine
        self.reputation_engine = reputation_engine
        self.window_monitor = window_monitor

        self._observer: Optional[Observer] = None
        self._running = False
        self._callbacks: List[Callable[[DownloadEvent], None]] = []
        self._recent_downloads: List[Dict[str, Any]] = []
        self._processed_files: set = set()
        self._lock = threading.Lock()

    def register_callback(self, callback: Callable[[DownloadEvent], None]):
        """Registers callback for completed download events."""
        self._callbacks.append(callback)

    def get_recent_downloads(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Returns list of recent downloads."""
        with self._lock:
            return list(self._recent_downloads[:limit])

    def start(self):
        """Starts monitoring the Downloads directory."""
        if self._running:
            return
        if not os.path.exists(self.downloads_dir):
            try:
                os.makedirs(self.downloads_dir, exist_ok=True)
            except Exception as e:
                logger.error(f"Cannot create downloads dir: {e}")
                return

        self._handler = DownloadFileSystemHandler(self)
        self._observer = Observer()
        self._observer.schedule(self._handler, path=self.downloads_dir, recursive=False)
        self._observer.start()
        self._running = True
        logger.info(f"DownloadMonitor active on: {self.downloads_dir}")

    def stop(self):
        """Stops the downloads observer."""
        if self._running and self._observer:
            self._observer.stop()
            self._observer.join(timeout=3.0)
            self._running = False
            logger.info("DownloadMonitor stopped.")

    def handle_file_event(self, file_path: str, immediate: bool = False):
        """Triggered when a file is created or renamed in Downloads."""
        if immediate:
            self._process_delayed(file_path, wait=False)
            return

        # Run asynchronously in background thread after brief delay to allow browser to finish flush & ADS write
        threading.Thread(
            target=self._process_delayed,
            args=(file_path, True),
            daemon=True,
            name="DIQ_DownloadScan",
        ).start()

    def _process_delayed(self, file_path: str, wait: bool = True):
        if wait:
            time.sleep(1.0)  # Brief wait for write flush
        file_name = os.path.basename(file_path)

        # Ignore active partial downloads
        if file_name.endswith(".crdownload") or file_name.endswith(".part") or file_name.endswith(".tmp"):
            return

        with self._lock:
            if file_path in self._processed_files:
                return
            self._processed_files.add(file_path)

        if not os.path.isfile(file_path):
            return

        event = self._analyze_download(file_path)
        if event:
            with self._lock:
                self._recent_downloads.insert(0, event.to_dict())
                if len(self._recent_downloads) > 50:
                    self._recent_downloads.pop()

            for cb in self._callbacks:
                try:
                    cb(event)
                except Exception as ex:
                    logger.error(f"Error in DownloadMonitor callback: {ex}")

    def _analyze_download(self, file_path: str) -> Optional[DownloadEvent]:
        """Inspects downloaded file, reads ADS Zone.Identifier, and executes scan."""
        try:
            file_name = os.path.basename(file_path)
            _, ext = os.path.splitext(file_name)
            ext_lower = ext.lower()
            file_size = os.path.getsize(file_path)

            # Human readable file size
            size_disp = self._format_size(file_size)

            # Compute SHA-256
            hasher = hashlib.sha256()
            try:
                with open(file_path, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)
                sha256 = hasher.hexdigest()
            except Exception:
                sha256 = "N/A"

            # Extract origin domain from Windows Zone.Identifier
            source_domain, source_url = self._extract_zone_identifier(file_path)

            # If not found in Zone.Identifier, check active browser context
            if source_domain == "Unknown" and self.window_monitor:
                curr_act = self.window_monitor.get_current_activity()
                if curr_act and curr_act.get("is_browser") and curr_act.get("domain"):
                    source_domain = curr_act["domain"]

            # Perform layered security scans
            signals = []
            risk_score = 0
            scan_verdict = "CLEAN"

            # Check dangerous extensions
            if ext_lower in (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com", ".jar"):
                signals.append("executable_downloaded")
                risk_score += 20

            # 1. Reputation Check
            if self.reputation_engine:
                try:
                    rep = self.reputation_engine.check_file(file_path)
                    if rep.get("verdict") == "MALICIOUS":
                        signals.append("known_malicious_hash")
                        risk_score += 50
                        scan_verdict = "MALICIOUS"
                except Exception as e:
                    logger.debug(f"Reputation scan err: {e}")

            # 2. YARA Scan
            if self.yara_engine and scan_verdict != "MALICIOUS":
                try:
                    yara_res = self.yara_engine.scan_file(file_path)
                    if yara_res.get("has_matches"):
                        signals.append("yara_rule_matched")
                        risk_score += 35
                        scan_verdict = "SUSPICIOUS"
                except Exception as e:
                    logger.debug(f"YARA scan err: {e}")

            # 3. Static Entropy Scan
            if self.static_analyzer and scan_verdict == "CLEAN":
                try:
                    stat_res = self.static_analyzer.analyze_file(file_path)
                    if stat_res.get("signals"):
                        signals.extend(stat_res["signals"])
                        risk_score += 25
                        scan_verdict = "SUSPICIOUS"
                except Exception as e:
                    logger.debug(f"Static analyzer err: {e}")

            if risk_score >= 60:
                scan_verdict = "MALICIOUS"
            elif risk_score >= 25:
                scan_verdict = "SUSPICIOUS"
            else:
                scan_verdict = "CLEAN"

            # Active process responsible (if browser in foreground)
            responsible_proc = None
            if self.window_monitor:
                curr_act = self.window_monitor.get_current_activity()
                if curr_act:
                    responsible_proc = curr_act.get("process_name")

            logger.info(
                f"[DOWNLOAD] {file_name} ({size_disp}) from [{source_domain}] - Verdict: {scan_verdict} ({risk_score}/100)"
            )

            return DownloadEvent(
                file_name=file_name,
                file_type=ext_lower or "unknown",
                source_domain=source_domain,
                source_url=source_url,
                download_timestamp=datetime.now(timezone.utc).isoformat(),
                destination_path=file_path,
                file_size_bytes=file_size,
                file_size_display=size_disp,
                scan_verdict=scan_verdict,
                risk_score=risk_score,
                risk_signals=signals,
                sha256=sha256,
                process_name=responsible_proc,
            )
        except Exception as e:
            logger.error(f"Error analyzing download {file_path}: {e}")
            return None

    def _extract_zone_identifier(self, file_path: str) -> (str, Optional[str]):
        """Reads Windows NTFS Zone.Identifier Alternate Data Stream (ADS)."""
        if sys.platform != "win32":
            return "Unknown", None

        ads_path = f"{file_path}:Zone.Identifier"
        if not os.path.exists(ads_path):
            return "Unknown", None

        try:
            with open(ads_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            host_url = None
            referrer_url = None

            for line in content.splitlines():
                if line.startswith("HostUrl="):
                    host_url = line.split("=", 1)[1].strip()
                elif line.startswith("ReferrerUrl="):
                    referrer_url = line.split("=", 1)[1].strip()

            target_url = host_url or referrer_url
            if target_url:
                parsed = urlparse(target_url)
                domain = parsed.netloc or parsed.path.split("/")[0]
                # Strip port if present
                domain = domain.split(":")[0].lower()
                return (domain or "Unknown"), target_url
        except Exception as e:
            logger.debug(f"Zone.Identifier read err: {e}")

        return "Unknown", None

    def _format_size(self, size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

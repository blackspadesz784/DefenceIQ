"""DefenceIQ Active Window and Browser Tab Monitor.

Tracks currently active applications, browser windows, active tab titles,
domains, and activity duration on the endpoint.
Enforces strict privacy: redacts sensitive page titles, passwords, search tokens,
and authentication forms.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("DefenceIQ.WindowMonitor")

# Known web browsers
BROWSER_PROCESSES = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "opera.exe": "Opera",
    "vivaldi.exe": "Vivaldi",
    "iexplore.exe": "Internet Explorer",
}

# Sensitive title patterns that must be redacted for privacy
SENSITIVE_PATTERNS = [
    re.compile(r"password|passwd|pwd|passcode", re.IGNORECASE),
    re.compile(r"login|sign in|signin|log in|2fa|otp|authenticat", re.IGNORECASE),
    re.compile(r"bank|banking|credit card|cvv|paypal", re.IGNORECASE),
    re.compile(r"secret|private|token|bearer|api_key|apikey", re.IGNORECASE),
    re.compile(r"incognito|private browsing|inprivate", re.IGNORECASE),
    re.compile(r"bitwarden|keepass|1password|lastpass|dashlane", re.IGNORECASE),
]


@dataclass
class WindowActivity:
    """Telemetry structure for active window/application."""

    app_name: str = "Unknown"
    process_name: str = ""
    pid: int = 0
    window_title: str = ""
    is_browser: bool = False
    browser_name: Optional[str] = None
    tab_title: Optional[str] = None
    domain: Optional[str] = None
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: int = 0
    privacy_redacted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WindowMonitor:
    """Continuously tracks the active foreground window and browser tab."""

    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._current_activity: Optional[WindowActivity] = None
        self._activity_start_time: float = time.time()
        self._recent_activities: List[Dict[str, Any]] = []
        self._callbacks: List[Callable[[WindowActivity], None]] = []

    def register_callback(self, callback: Callable[[WindowActivity], None]):
        """Register a callback for window transition events."""
        self._callbacks.append(callback)

    def get_current_activity(self) -> Optional[Dict[str, Any]]:
        """Returns the current active window state with calculated duration."""
        with self._lock:
            if not self._current_activity:
                return None
            curr = WindowActivity(**self._current_activity.to_dict())
            curr.duration_seconds = max(0, int(time.time() - self._activity_start_time))
            return curr.to_dict()

    def get_recent_activities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns a list of recent window/tab activities."""
        with self._lock:
            activities = list(self._recent_activities)
            curr = None
            if self._current_activity:
                curr_act = WindowActivity(**self._current_activity.to_dict())
                curr_act.duration_seconds = max(0, int(time.time() - self._activity_start_time))
                curr = curr_act.to_dict()
            if curr:
                return [curr] + activities[: limit - 1]
            return activities[:limit]

    def start(self):
        """Starts the background window polling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, name="DIQ_WindowMonitor", daemon=True
        )
        self._thread.start()
        logger.info("WindowMonitor started.")

    def stop(self):
        """Stops the window polling thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("WindowMonitor stopped.")

    def _monitor_loop(self):
        """Main polling loop checking active foreground window."""
        while self._running:
            try:
                activity = self._get_active_window()
                if activity:
                    self._update_activity(activity)
            except Exception as e:
                logger.debug(f"Window monitor poll note: {e}")
            time.sleep(self.poll_interval)

    def _update_activity(self, new_act: WindowActivity):
        """Compares new activity with current and updates timers/history."""
        with self._lock:
            if (
                self._current_activity is None
                or self._current_activity.process_name != new_act.process_name
                or self._current_activity.window_title != new_act.window_title
            ):
                # Save previous activity to history
                if self._current_activity:
                    self._current_activity.duration_seconds = max(
                        1, int(time.time() - self._activity_start_time)
                    )
                    self._recent_activities.insert(
                        0, self._current_activity.to_dict()
                    )
                    if len(self._recent_activities) > 30:
                        self._recent_activities.pop()

                self._current_activity = new_act
                self._activity_start_time = time.time()

                for cb in self._callbacks:
                    try:
                        cb(new_act)
                    except Exception as ex:
                        logger.error(f"WindowMonitor callback error: {ex}")

    def _get_active_window(self) -> Optional[WindowActivity]:
        """Queries the OS for current foreground window details."""
        if sys.platform != "win32":
            return None

        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return None

            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            raw_title = buff.value.strip()

            if not raw_title:
                return None

            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = pid.value

            import psutil
            try:
                proc = psutil.Process(pid_val)
                proc_name = proc.name()
                app_name = os.path.splitext(proc_name)[0]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "unknown.exe"
                app_name = "Unknown"

            # Parse browser details if process is a known browser
            proc_lower = proc_name.lower()
            is_browser = proc_lower in BROWSER_PROCESSES
            browser_name = BROWSER_PROCESSES.get(proc_lower)

            tab_title = None
            domain = None
            privacy_redacted = False

            # Check privacy redaction
            if self._is_sensitive(raw_title):
                clean_title = "[Private / Sensitive Page Redacted]"
                privacy_redacted = True
            else:
                clean_title = raw_title

            if is_browser and not privacy_redacted:
                tab_title, domain = self._parse_browser_title(clean_title, browser_name)

            return WindowActivity(
                app_name=app_name,
                process_name=proc_name,
                pid=pid_val,
                window_title=clean_title,
                is_browser=is_browser,
                browser_name=browser_name,
                tab_title=tab_title or clean_title,
                domain=domain,
                start_time=datetime.now(timezone.utc).isoformat(),
                duration_seconds=0,
                privacy_redacted=privacy_redacted,
            )
        except Exception as e:
            logger.debug(f"Error reading foreground window: {e}")
            return None

    def _is_sensitive(self, title: str) -> bool:
        """Determines if a title contains sensitive or private contents."""
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(title):
                return True
        return False

    def _parse_browser_title(
        self, title: str, browser_name: Optional[str]
    ) -> (Optional[str], Optional[str]):
        """Strips browser suffixes and extracts tab title and domain/site name."""
        tab_title = title
        domain = None

        # Strip browser name suffix (e.g. " - Google Chrome")
        if browser_name:
            suffix = f" - {browser_name}"
            if tab_title.endswith(suffix):
                tab_title = tab_title[: -len(suffix)].strip()
            suffix_dash = f" — {browser_name}"
            if tab_title.endswith(suffix_dash):
                tab_title = tab_title[: -len(suffix_dash)].strip()

        # Check if tab title contains a URL
        url_match = re.search(r"https?://([a-zA-Z0-9.\-]+)", tab_title)
        if url_match:
            domain = url_match.group(1).lower()
        else:
            # Common web service title patterns e.g. "Page - GitHub", "GitHub - Profile"
            parts = [p.strip() for p in re.split(r"[-|—•:]", tab_title) if p.strip()]
            known_brands = {
                "github": "github.com",
                "google": "google.com",
                "googlesearch": "google.com",
                "youtube": "youtube.com",
                "stackoverflow": "stackoverflow.com",
                "reddit": "reddit.com",
                "chatgpt": "chatgpt.com",
                "openai": "openai.com",
                "claude": "claude.ai",
                "microsoft": "microsoft.com",
                "wikipedia": "wikipedia.org",
                "amazon": "amazon.com",
                "twitter": "x.com",
                "x": "x.com",
                "linkedin": "linkedin.com",
                "medium": "medium.com",
                "netflix": "netflix.com",
            }
            for p in parts:
                clean_p = p.lower().replace(" ", "")
                if clean_p in known_brands:
                    domain = known_brands[clean_p]
                    break

        return tab_title, domain

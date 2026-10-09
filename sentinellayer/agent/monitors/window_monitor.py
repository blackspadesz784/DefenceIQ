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

# Friendly display names for common desktop apps
FRIENDLY_APP_NAMES = {
    "msedge.exe": "Microsoft Edge",
    "chrome.exe": "Google Chrome",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "opera.exe": "Opera Browser",
    "vivaldi.exe": "Vivaldi",
    "code.exe": "Visual Studio Code",
    "antigravity ide.exe": "Antigravity IDE",
    "devenv.exe": "Visual Studio",
    "pycharm64.exe": "PyCharm",
    "idea64.exe": "IntelliJ IDEA",
    "sublime_text.exe": "Sublime Text",
    "notepad++.exe": "Notepad++",
    "notepad.exe": "Notepad",
    "explorer.exe": "File Explorer",
    "powershell.exe": "Windows PowerShell",
    "pwsh.exe": "PowerShell 7",
    "cmd.exe": "Command Prompt",
    "windowsterminal.exe": "Windows Terminal",
    "taskmgr.exe": "Task Manager",
    "settings.exe": "Windows Settings",
    "systemsettings.exe": "Windows Settings",
    "slack.exe": "Slack",
    "discord.exe": "Discord",
    "spotify.exe": "Spotify",
    "teams.exe": "Microsoft Teams",
    "ms-teams.exe": "Microsoft Teams",
    "zoom.exe": "Zoom Meetings",
    "telegram.exe": "Telegram Desktop",
    "whatsapp.root.exe": "WhatsApp Desktop",
    "whatsapp.exe": "WhatsApp Desktop",
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "outlook.exe": "Microsoft Outlook",
    "vlc.exe": "VLC Media Player",
    "steam.exe": "Steam",
    "calc.exe": "Calculator",
    "mspaint.exe": "Paint",
    "pdf24.exe": "PDF24 Creator",
    "wps.exe": "WPS Office",
}

APP_CATEGORIES = {
    "chrome.exe": "Web Browser",
    "msedge.exe": "Web Browser",
    "firefox.exe": "Web Browser",
    "brave.exe": "Web Browser",
    "opera.exe": "Web Browser",
    "vivaldi.exe": "Web Browser",
    "code.exe": "Development",
    "antigravity ide.exe": "Development",
    "devenv.exe": "Development",
    "pycharm64.exe": "Development",
    "idea64.exe": "Development",
    "sublime_text.exe": "Development",
    "notepad++.exe": "Text Editor",
    "notepad.exe": "Text Editor",
    "explorer.exe": "File Management",
    "powershell.exe": "Terminal / Shell",
    "pwsh.exe": "Terminal / Shell",
    "cmd.exe": "Terminal / Shell",
    "windowsterminal.exe": "Terminal / Shell",
    "taskmgr.exe": "System Utility",
    "settings.exe": "System Settings",
    "systemsettings.exe": "System Settings",
    "slack.exe": "Communication",
    "discord.exe": "Communication",
    "spotify.exe": "Media & Audio",
    "teams.exe": "Collaboration",
    "ms-teams.exe": "Collaboration",
    "zoom.exe": "Conferencing",
    "telegram.exe": "Messaging",
    "whatsapp.root.exe": "Messaging",
    "whatsapp.exe": "Messaging",
    "winword.exe": "Office / Documents",
    "excel.exe": "Office / Spreadsheets",
    "powerpnt.exe": "Office / Presentations",
    "outlook.exe": "Email / PIM",
    "vlc.exe": "Media Player",
    "steam.exe": "Gaming",
    "pdf24.exe": "Document Utilities",
    "wps.exe": "Office / Productivity",
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
        self._closed_apps: List[Dict[str, Any]] = []
        self._last_open_apps: Dict[str, Dict[str, Any]] = {}

    def register_callback(self, callback: Callable[[WindowActivity], None]):
        """Register a callback for window transition events."""
        self._callbacks.append(callback)

    def get_current_activity(self) -> Optional[Dict[str, Any]]:
        """Returns the current active window state with calculated duration."""
        with self._lock:
            if not self._current_activity:
                act = self._get_active_window()
                if act:
                    self._current_activity = act
                    self._activity_start_time = time.time()
                    return act.to_dict()
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

    def get_open_applications(self) -> List[Dict[str, Any]]:
        """Returns comprehensive list of currently open and recently closed GUI applications.

        Extracts friendly names, window titles, exact launch times, running durations,
        foreground status, and indicates whether each application is still currently open.
        """
        if sys.platform != "win32":
            return []

        import ctypes
        import psutil

        user32 = ctypes.windll.user32
        WINSTA_ALL = 0x37F
        DESKTOP_ALL = 0x1FF

        try:
            hwinsta = user32.OpenWindowStationW("WinSta0", False, WINSTA_ALL)
            if hwinsta:
                user32.SetProcessWindowStation(hwinsta)
            hdesk = user32.OpenDesktopW("default", 0, False, DESKTOP_ALL)
        except Exception:
            hdesk = None

        fg_hwnd = user32.GetForegroundWindow()
        fg_pid = 0
        if fg_hwnd:
            p_val = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(fg_hwnd, ctypes.byref(p_val))
            fg_pid = p_val.value

        hwnds = []
        def enum_cb(h, _):
            hwnds.append(h)
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        try:
            if hdesk:
                user32.EnumDesktopWindows(hdesk, WNDENUMPROC(enum_cb), 0)
            else:
                user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
        except Exception:
            pass

        current_apps = []
        current_app_keys = set()
        seen = set()

        ignore_procs = {
            "svchost.exe", "shellexperiencehost.exe", "searchhost.exe",
            "lockapp.exe", "dwm.exe", "taskhostw.exe", "textinputhost.exe",
            "startmenuexperiencehost.exe", "unsecapp.exe", "crossdeviceservice.exe"
        }

        for h in hwnds:
            try:
                if not user32.IsWindowVisible(h):
                    continue
                length = user32.GetWindowTextLengthW(h)
                if length <= 0:
                    continue
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(h, buff, length + 1)
                title = buff.value.strip()
                if not title:
                    continue

                t_low = title.lower()
                if any(ign in t_low for ign in ("olemainthread", "olechannel", "dwm notification", "task host", "input experience", "gdi+ window", "program manager", "quick settings")):
                    continue

                p_val = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(h, ctypes.byref(p_val))
                pid = p_val.value
                if pid <= 0:
                    continue

                try:
                    p = psutil.Process(pid)
                    p_name = p.name()
                    c_time = p.create_time()
                except Exception:
                    continue

                p_low = p_name.lower()
                if p_low in ignore_procs:
                    continue

                friendly = FRIENDLY_APP_NAMES.get(p_low)
                if not friendly:
                    base = os.path.splitext(p_name)[0]
                    friendly = base.replace("_", " ").replace("-", " ").title()

                category = APP_CATEGORIES.get(p_low, "Application")

                is_fg = (pid == fg_pid or h == fg_hwnd)
                dt = datetime.fromtimestamp(c_time)
                open_time_str = dt.strftime("%I:%M %p")

                duration_secs = max(1, int(time.time() - c_time))
                mins = duration_secs // 60
                hrs = mins // 60
                if hrs > 0:
                    dur_str = f"{hrs}h {mins % 60}m"
                else:
                    dur_str = f"{max(1, mins)}m"

                clean_title = "[Private Page Redacted]" if self._is_sensitive(title) else title

                key = (p_low, clean_title)
                if key not in seen:
                    seen.add(key)
                    app_dict = {
                        "app_name": friendly,
                        "process_name": p_name,
                        "pid": pid,
                        "window_title": clean_title,
                        "category": category,
                        "opened_at": open_time_str,
                        "duration": dur_str,
                        "is_open": True,
                        "is_foreground": is_fg,
                        "status": "Active Now" if is_fg else "Currently Open",
                    }
                    current_apps.append(app_dict)
                    current_app_keys.add(friendly)
            except Exception:
                continue

        with self._lock:
            # Check for recently closed apps
            now_str = datetime.now().strftime("%I:%M %p")
            for prev_name, prev_info in list(self._last_open_apps.items()):
                if prev_name not in current_app_keys and prev_info.get("is_open", True):
                    closed_item = dict(prev_info)
                    closed_item["is_open"] = False
                    closed_item["is_foreground"] = False
                    closed_item["status"] = "Recently Closed"
                    closed_item["closed_at"] = now_str
                    self._closed_apps.insert(0, closed_item)
                    if len(self._closed_apps) > 8:
                        self._closed_apps.pop()

            self._last_open_apps = {a["app_name"]: a for a in current_apps}
            current_apps.sort(key=lambda x: (not x["is_foreground"], x["opened_at"]))
            return current_apps + self._closed_apps

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
            raw_title = ""
            pid_val = 0
            proc_name = ""

            if hwnd:
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buff, length + 1)
                    raw_title = buff.value.strip()

                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                pid_val = pid.value
                if pid_val > 0:
                    import psutil
                    try:
                        proc = psutil.Process(pid_val)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = ""

            # If foreground window was empty or session is headless, detect top user GUI app
            if not raw_title or not proc_name:
                import psutil
                gui_candidates = []
                for p in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        p_name = p.info['name']
                        p_low = p_name.lower()
                        if p_low in FRIENDLY_APP_NAMES and p_low != "explorer.exe":
                            gui_candidates.append((p.info['pid'], p_name, p.info.get('cpu_percent', 0.0)))
                    except Exception:
                        pass
                if gui_candidates:
                    gui_candidates.sort(key=lambda x: x[2], reverse=True)
                    top_pid, top_name, _ = gui_candidates[0]
                    pid_val = top_pid
                    proc_name = top_name
                    friendly = FRIENDLY_APP_NAMES.get(proc_name.lower(), proc_name)
                    raw_title = f"{friendly} - Active Workspace"
                elif not raw_title and proc_name:
                    friendly = FRIENDLY_APP_NAMES.get(proc_name.lower(), proc_name)
                    raw_title = f"{friendly} (Foreground Window)"
                elif not raw_title:
                    proc_name = "explorer.exe"
                    raw_title = "Windows File Explorer / Desktop"

            proc_lower = proc_name.lower()
            app_name = FRIENDLY_APP_NAMES.get(proc_lower)
            if not app_name:
                base = os.path.splitext(proc_name)[0]
                app_name = base.replace("_", " ").replace("-", " ").title()

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

"""Tests for WindowMonitor and DownloadMonitor."""

import os
import tempfile
import time
from unittest.mock import MagicMock, patch

from sentinellayer.agent.monitors.window_monitor import WindowActivity, WindowMonitor
from sentinellayer.agent.monitors.download_monitor import DownloadEvent, DownloadMonitor


def test_window_activity_serialization():
    act = WindowActivity(
        app_name="Code",
        process_name="Code.exe",
        pid=1234,
        window_title="DefenceIQ - Visual Studio Code",
        is_browser=False,
        tab_title=None,
        domain=None,
        duration_seconds=42,
    )
    d = act.to_dict()
    assert d["app_name"] == "Code"
    assert d["process_name"] == "Code.exe"
    assert d["duration_seconds"] == 42
    assert d["privacy_redacted"] is False


def test_window_monitor_browser_and_privacy_redaction():
    mon = WindowMonitor()

    # 1. Browser title parsing
    title, domain = mon._parse_browser_title("GitHub - blackspadesz784 - Google Chrome", "Google Chrome")
    assert title == "GitHub - blackspadesz784"
    assert domain == "github.com"

    # 2. Privacy redaction check
    assert mon._is_sensitive("Bitwarden Password Manager - Google Chrome") is True
    assert mon._is_sensitive("Login to Your Bank Account - Microsoft Edge") is True
    assert mon._is_sensitive("React Documentation - Google Chrome") is False


def test_download_monitor_file_analysis():
    with tempfile.TemporaryDirectory() as tmp_dir:
        mon = DownloadMonitor(downloads_dir=tmp_dir)

        test_file = os.path.join(tmp_dir, "installer.exe")
        with open(test_file, "wb") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"A" * 1024)

        event = mon._analyze_download(test_file)
        assert event is not None
        assert event.file_name == "installer.exe"
        assert event.file_type == ".exe"
        assert event.file_size_bytes > 0
        assert "executable_downloaded" in event.risk_signals
        assert event.scan_verdict in ("CLEAN", "SUSPICIOUS", "MALICIOUS")


def test_window_monitor_duration_and_history():
    mon = WindowMonitor()
    act1 = WindowActivity(app_name="Chrome", process_name="chrome.exe", window_title="Google - Google Chrome")
    mon._update_activity(act1)
    curr = mon.get_current_activity()
    assert curr is not None
    assert curr["app_name"] == "Chrome"

    # Simulate transition to another window
    time.sleep(0.05)
    act2 = WindowActivity(app_name="Terminal", process_name="wt.exe", window_title="PowerShell")
    mon._update_activity(act2)

    recent = mon.get_recent_activities(limit=5)
    assert len(recent) >= 2
    assert recent[0]["app_name"] == "Terminal"
    assert recent[1]["app_name"] == "Chrome"


def test_download_monitor_callbacks_and_history():
    with tempfile.TemporaryDirectory() as tmp_dir:
        mon = DownloadMonitor(downloads_dir=tmp_dir)
        events_received = []
        mon.register_callback(lambda ev: events_received.append(ev))

        test_file = os.path.join(tmp_dir, "document.pdf")
        with open(test_file, "wb") as f:
            f.write(b"%PDF-1.4 sample pdf file content")

        mon.handle_file_event(test_file, immediate=True)
        assert len(events_received) == 1
        assert events_received[0].file_name == "document.pdf"

        history = mon.get_recent_downloads(limit=5)
        assert len(history) == 1
        assert history[0]["file_name"] == "document.pdf"


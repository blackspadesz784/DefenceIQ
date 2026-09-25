"""Unit tests for FileMonitor, FileEvent, and Shannon entropy calculations."""

import json
import os
import sys
import tempfile
import time
import pytest

from sentinellayer.agent.config.settings import FileMonitorConfig
from sentinellayer.agent.monitors.file_monitor import (
    FileEvent,
    FileMonitor,
    RollingWindowTracker,
    calculate_entropy,
    get_file_entropy,
)


def test_calculate_entropy_text_vs_random():
    """Verify Shannon entropy computation for empty, uniform, text, and random data."""
    # Empty
    assert calculate_entropy(b"") == 0.0

    # Uniform
    assert calculate_entropy(b"A" * 500) == 0.0

    # Plain text English
    text_data = b"The quick brown fox jumps over the lazy dog. DefenceIQ endpoint security agent."
    text_entropy = calculate_entropy(text_data)
    assert 3.0 <= text_entropy <= 5.0

    # Highly random / encrypted (pseudorandom bytes)
    random_bytes = os.urandom(2048)
    rand_entropy = calculate_entropy(random_bytes)
    assert rand_entropy >= 7.5


def test_file_event_serialization():
    """Verify FileEvent dataclass serializes to dictionary and JSON."""
    event = FileEvent(
        event_type="FILE_CREATED",
        file_path="C:\\Users\\User\\Downloads\\sample.dll",
        file_name="sample.dll",
        extension=".dll",
        file_size_bytes=10240,
        entropy=6.8,
        is_executable=True,
        is_sensitive_location=False,
        signals=["new_executable_file"],
    )

    data = event.to_dict()
    assert data["file_name"] == "sample.dll"
    assert data["extension"] == ".dll"
    assert data["is_executable"] is True
    assert "new_executable_file" in data["signals"]
    assert data["event_id"] is not None

    json_str = event.to_json()
    parsed = json.loads(json_str)
    assert parsed["entropy"] == 6.8
    assert parsed["file_size_bytes"] == 10240


def test_process_file_change_new_executable():
    """Verify newly created executable/DLL files generate appropriate signals."""
    monitor = FileMonitor()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"MZ\x90\x00Dummy binary")
        tmp_path = tmp.name

    try:
        event = monitor.process_file_change("FILE_CREATED", tmp_path)
        assert event is not None
        assert event.is_executable is True
        assert "new_executable_file" in event.signals
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def test_sensitive_folder_detection():
    """Verify changes inside sensitive system locations are detected."""
    config = FileMonitorConfig(
        sensitive_paths=["C:\\Windows\\System32", "%TEMP%\\defenceiq_sensitive_test"]
    )
    monitor = FileMonitor(config=config)

    test_path = os.path.expandvars("%TEMP%\\defenceiq_sensitive_test\\payload.txt")
    assert monitor.is_sensitive_path(test_path) is True

    event = monitor.process_file_change("FILE_CREATED", test_path)
    assert event is not None
    assert event.is_sensitive_location is True
    assert "sensitive_folder_modification" in event.signals


def test_rolling_window_rapid_modifications_and_mass_encryption():
    """Verify rolling window detects rapid modification bursts and mass high-entropy encryption."""
    config = FileMonitorConfig(
        rapid_modification_threshold=5,
        mass_encryption_threshold=3,
        window_seconds=3.0,
        entropy_threshold=7.2,
    )
    monitor = FileMonitor(config=config)

    # Simulate 5 files modified with high entropy
    events = []
    for i in range(5):
        # We manually record events with simulated high entropy
        monitor.tracker.record_event("FILE_MODIFIED", f"C:\\dummy_{i}.enc", entropy=7.8)

    # Now process a 6th event
    event = monitor.process_file_change("FILE_MODIFIED", "C:\\dummy_trigger.enc")
    assert event is not None
    assert "rapid_file_modifications" in event.signals
    assert "modified_encrypted_many_files" in event.signals


def test_rolling_window_mass_deletions():
    """Verify rolling window detects mass file deletion spikes."""
    config = FileMonitorConfig(
        mass_deletion_threshold=4,
        window_seconds=3.0,
    )
    monitor = FileMonitor(config=config)

    for i in range(4):
        monitor.tracker.record_event("FILE_DELETED", f"C:\\file_{i}.txt", entropy=None)

    event = monitor.process_file_change("FILE_DELETED", "C:\\file_trigger.txt")
    assert event is not None
    assert "mass_file_deletions" in event.signals


def test_get_file_entropy():
    """Verify get_file_entropy reads file and calculates entropy correctly."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"Normal predictable plain text words.")
        tmp_path = tmp.name

    try:
        entropy = get_file_entropy(tmp_path)
        assert entropy is not None
        assert 2.0 < entropy < 5.0
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def test_watchdog_live_directory_monitoring():
    """Verify live filesystem creation detection via Watchdog in a temporary directory."""
    with tempfile.TemporaryDirectory(prefix="defenceiq_test_") as tmp_dir:
        monitor = FileMonitor()
        captured_events = []
        monitor.register_callback(lambda ev: captured_events.append(ev))

        monitor.start(watch_paths=[tmp_dir])
        time.sleep(0.3)

        # Create a test file
        test_file = os.path.join(tmp_dir, "test_agent_artifact.dll")
        with open(test_file, "wb") as f:
            f.write(b"MZ\x00\x00test content")

        # Allow watchdog thread to catch the Windows notification
        time.sleep(0.5)
        monitor.stop()

        # Check captured events
        matching = [ev for ev in captured_events if "test_agent_artifact.dll" in ev.file_path]
        assert len(matching) >= 1
        assert matching[0].is_executable is True
        assert matching[0].extension == ".dll"

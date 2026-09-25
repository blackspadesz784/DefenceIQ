"""Unit tests for ProcessMonitor and ProcessEvent."""

import asyncio
import json
import os
import sys
from unittest.mock import MagicMock, patch
import pytest

from sentinellayer.agent.config.settings import ProcessMonitorConfig
from sentinellayer.agent.monitors.process_monitor import (
    ProcessEvent,
    ProcessMonitor,
    verify_file_signature,
)


def test_process_event_serialization():
    """Verify ProcessEvent initializes properly and serializes to valid JSON."""
    event = ProcessEvent(
        event_type="PROCESS_CREATED",
        pid=1234,
        ppid=5678,
        name="test_proc.exe",
        exe="C:\\Tools\\test_proc.exe",
        cmdline=["test_proc.exe", "-arg"],
        username="SYSTEM",
        parent_name="parent.exe",
        cpu_percent=12.5,
        memory_mb=45.0,
        is_signed=False,
        signature_status="UNSIGNED",
        signals=["spawned_script_shell"],
    )

    data = event.to_dict()
    assert data["pid"] == 1234
    assert data["name"] == "test_proc.exe"
    assert data["event_type"] == "PROCESS_CREATED"
    assert "spawned_script_shell" in data["signals"]
    assert data["event_id"] is not None

    json_str = event.to_json()
    parsed = json.loads(json_str)
    assert parsed["pid"] == 1234
    assert parsed["signature_status"] == "UNSIGNED"


def test_evaluate_signals_suspicious_shell():
    """Verify suspicious administrative shell names raise signal."""
    monitor = ProcessMonitor()

    pdata = {
        "pid": 9999,
        "ppid": 1000,
        "name": "powershell.exe",
        "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": ["powershell.exe", "-ExecutionPolicy", "Bypass"],
        "username": "user",
        "parent_name": "explorer.exe",
        "parent_exe": None,
        "cpu_percent": 2.0,
        "memory_mb": 50.0,
    }

    signals = monitor.evaluate_signals(pdata)
    assert "spawned_script_shell" in signals


def test_evaluate_signals_suspicious_parent_child():
    """Verify Office/browser app spawning a shell raises suspicious_parent_child."""
    monitor = ProcessMonitor()

    pdata = {
        "pid": 4321,
        "ppid": 2000,
        "name": "cmd.exe",
        "exe": "C:\\Windows\\System32\\cmd.exe",
        "cmdline": ["cmd.exe", "/c", "whoami"],
        "username": "user",
        "parent_name": "winword.exe",
        "parent_exe": "C:\\Program Files\\Microsoft Office\\winword.exe",
        "cpu_percent": 1.0,
        "memory_mb": 15.0,
    }

    signals = monitor.evaluate_signals(pdata)
    assert "spawned_script_shell" in signals
    assert "suspicious_parent_child" in signals


def test_evaluate_signals_resource_spikes():
    """Verify CPU and memory exceeding configured thresholds raise signals."""
    config = ProcessMonitorConfig(
        cpu_spike_threshold_percent=80.0,
        memory_spike_threshold_mb=400.0,
    )
    monitor = ProcessMonitor(config=config)

    pdata = {
        "pid": 5555,
        "ppid": 1000,
        "name": "worker.exe",
        "exe": None,
        "cmdline": [],
        "username": "user",
        "parent_name": "explorer.exe",
        "parent_exe": None,
        "cpu_percent": 95.0,
        "memory_mb": 650.0,
    }

    signals = monitor.evaluate_signals(pdata)
    assert "resource_spike_cpu" in signals
    assert "resource_spike_memory" in signals


def test_verify_file_signature_nonexistent():
    """Verify signature check handles missing or null files gracefully."""
    res_none = verify_file_signature(None)
    assert res_none["is_signed"] is False
    assert res_none["status"] == "NO_PATH"

    res_missing = verify_file_signature("C:\\non_existent_file_12345.exe")
    assert res_missing["is_signed"] is False
    assert res_missing["status"] == "NOT_FOUND"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Authenticode only")
def test_verify_file_signature_python_executable():
    """Verify signature check on real Python interpreter on Windows."""
    res = verify_file_signature(sys.executable)
    assert isinstance(res, dict)
    assert "is_signed" in res
    assert "status" in res


def test_scan_iteration_new_and_terminated_process():
    """Verify scan_iteration detects new processes and terminations."""
    event_queue = asyncio.Queue()
    monitor = ProcessMonitor(event_bus=event_queue)

    # Mock psutil Process object
    mock_proc1 = MagicMock()
    mock_proc1.pid = 101
    mock_proc1.name.return_value = "baseline.exe"
    mock_proc1.exe.return_value = "C:\\baseline.exe"
    mock_proc1.cmdline.return_value = ["baseline.exe"]
    mock_proc1.username.return_value = "user"
    mock_proc1.ppid.return_value = 1
    mock_proc1.cpu_percent.return_value = 0.5
    mock_proc1.memory_info.return_value = MagicMock(rss=10 * 1024 * 1024)
    mock_proc1.oneshot.return_value.__enter__.return_value = None
    mock_proc1.oneshot.return_value.__exit__.return_value = None

    with patch("psutil.process_iter", return_value=[mock_proc1]):
        monitor.initialize_baseline()

    assert 101 in monitor._known_processes

    # Next iteration: PID 101 is still running, and new PID 102 appears
    mock_proc2 = MagicMock()
    mock_proc2.pid = 102
    mock_proc2.name.return_value = "calc.exe"
    mock_proc2.exe.return_value = "C:\\Windows\\System32\\calc.exe"
    mock_proc2.cmdline.return_value = ["calc.exe"]
    mock_proc2.username.return_value = "user"
    mock_proc2.ppid.return_value = 101
    mock_proc2.cpu_percent.return_value = 1.0
    mock_proc2.memory_info.return_value = MagicMock(rss=25 * 1024 * 1024)
    mock_proc2.oneshot.return_value.__enter__.return_value = None
    mock_proc2.oneshot.return_value.__exit__.return_value = None

    emitted_events = []
    monitor.register_callback(lambda ev: emitted_events.append(ev))

    with patch("psutil.process_iter", return_value=[mock_proc1, mock_proc2]):
        events = monitor.scan_iteration()

    # Verify new process event emitted
    assert len(events) == 1
    assert events[0].event_type == "PROCESS_CREATED"
    assert events[0].pid == 102
    assert events[0].name == "calc.exe"
    assert len(emitted_events) == 1

    # Next iteration: PID 102 terminates, only PID 101 remains
    with patch("psutil.process_iter", return_value=[mock_proc1]):
        events_term = monitor.scan_iteration()

    assert len(events_term) == 1
    assert events_term[0].event_type == "PROCESS_TERMINATED"
    assert events_term[0].pid == 102
    assert 102 not in monitor._known_processes

"""Unit tests for Self-Monitoring and Tamper Protection.

Tests TamperEvent serialization, file integrity auditing, process termination
attempt detection, callback dispatch, and EventCorrelator integration.
"""

import os
import time
import pytest

from sentinellayer.agent.tamper_protection.self_monitor import SelfMonitor, TamperEvent
from sentinellayer.agent.ai_engine.event_correlator import EventCorrelator
from sentinellayer.agent.ai_engine.risk_scoring import RiskScoringEngine


def test_tamper_event_serialization():
    ev = TamperEvent(
        tamper_type="PROCESS_KILL_ATTEMPT",
        target="PID:1234",
        attacker_pid=5678,
        attacker_name="taskkill.exe",
        details="Attempted to kill agent",
        signals=["attempted_disable_security"],
        severity="CRITICAL",
    )
    d = ev.to_dict()
    assert d["tamper_type"] == "PROCESS_KILL_ATTEMPT"
    assert d["target"] == "PID:1234"
    assert d["attacker_pid"] == 5678
    assert d["attacker_name"] == "taskkill.exe"
    assert "attempted_disable_security" in d["signals"]
    assert d["severity"] == "CRITICAL"


def test_file_integrity_baseline_and_deletion(tmp_path):
    token_file = tmp_path / "pairing_token.key"
    token_file.write_text("SUPER_SECRET_TOKEN")

    monitor = SelfMonitor(monitored_files=[str(token_file)], agent_pid=9999)
    status = monitor.get_status()
    assert status["monitored_files_count"] == 1

    # Initially, no tampering
    events = monitor.check_file_integrity()
    assert len(events) == 0

    # Delete critical file
    os.remove(str(token_file))

    # Audit detects deletion
    events = monitor.check_file_integrity()
    assert len(events) == 1
    assert events[0].tamper_type == "FILE_DELETED"
    assert "attempted_disable_security" in events[0].signals
    assert "pairing_token.key" in events[0].details


def test_file_integrity_truncation(tmp_path):
    db_file = tmp_path / "defenceiq.db"
    db_file.write_bytes(b"SQLite format 3\x00" * 10)

    monitor = SelfMonitor(monitored_files=[str(db_file)], agent_pid=9999)

    # Truncate file to 0 bytes
    db_file.write_bytes(b"")

    events = monitor.check_file_integrity()
    assert len(events) == 1
    assert events[0].tamper_type == "FILE_MODIFIED"
    assert "0 bytes" in events[0].details
    assert "attempted_disable_security" in events[0].signals


def test_process_threats_detection_mocked():
    agent_pid = 4321
    monitor = SelfMonitor(agent_pid=agent_pid)

    mock_procs = [
        # 1. Benign process
        {"pid": 100, "name": "notepad.exe", "cmdline": ["notepad.exe", "notes.txt"]},
        # 2. taskkill targeting agent PID
        {
            "pid": 200,
            "name": "taskkill.exe",
            "cmdline": ["taskkill", "/f", "/pid", str(agent_pid)],
        },
        # 3. powershell Stop-Process targeting agent PID
        {
            "pid": 300,
            "name": "powershell.exe",
            "cmdline": ["powershell", "-Command", f"Stop-Process -Id {agent_pid} -Force"],
        },
        # 4. taskkill targeting unrelated PID
        {
            "pid": 400,
            "name": "taskkill.exe",
            "cmdline": ["taskkill", "/f", "/pid", "8888"],
        },
    ]

    events = monitor.check_process_threats(process_list=mock_procs)
    assert len(events) == 2

    # Verify event 1 (taskkill)
    assert events[0].attacker_pid == 200
    assert events[0].tamper_type == "PROCESS_KILL_ATTEMPT"
    assert "attempted_disable_security" in events[0].signals

    # Verify event 2 (powershell)
    assert events[1].attacker_pid == 300
    assert events[1].tamper_type == "PROCESS_KILL_ATTEMPT"
    assert "Stop-Process" in events[1].details


def test_callback_dispatch():
    dispatched = []
    monitor = SelfMonitor(agent_pid=1111, callback=lambda ev: dispatched.append(ev))

    mock_procs = [
        {"pid": 2222, "name": "pskill.exe", "cmdline": ["pskill", "1111"]},
    ]
    monitor.check_process_threats(mock_procs)
    assert len(dispatched) == 1
    assert dispatched[0].attacker_pid == 2222


def test_event_correlator_tamper_integration():
    scoring = RiskScoringEngine()
    correlator = EventCorrelator(scoring_engine=scoring)

    tamper_ev = TamperEvent(
        tamper_type="PROCESS_KILL_ATTEMPT",
        target="PID:9999",
        attacker_pid=7777,
        attacker_name="malware_stopper.exe",
        details="Attempted to stop DefenceIQ service",
        signals=["attempted_disable_security"],
    )

    incident = correlator.process_event(tamper_ev)
    assert incident is not None
    assert incident.root_pid == 7777
    assert incident.root_process_name == "malware_stopper.exe"
    assert "attempted_disable_security" in incident.signals
    assert incident.score_result.score == 25
    assert any(s.name == "attempted_disable_security" for s in incident.score_result.contributing_signals)

    # Adding a script shell signal elevates score to 45 (YELLOW)
    tamper_ev2 = TamperEvent(
        tamper_type="PROCESS_KILL_ATTEMPT",
        attacker_pid=7777,
        attacker_name="malware_stopper.exe",
        signals=["spawned_script_shell"],
    )
    incident2 = correlator.process_event(tamper_ev2)
    assert incident2.score_result.score == 45
    assert incident2.score_result.band == "YELLOW"


def test_watchdog_thread_lifecycle():
    monitor = SelfMonitor(agent_pid=9999)
    assert monitor.get_status()["running"] is False

    monitor.start(poll_interval=0.1)
    assert monitor.get_status()["running"] is True

    time.sleep(0.25)
    monitor.stop()
    assert monitor.get_status()["running"] is False

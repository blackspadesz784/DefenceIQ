"""Unit and integration tests for USB & Removable Storage Monitor."""

import os
import shutil
import tempfile
import pytest

from sentinellayer.agent.ai_engine.event_correlator import EventCorrelator
from sentinellayer.agent.ai_engine.risk_scoring import RiskScoringEngine
from sentinellayer.agent.config.settings import Settings, USBMonitorConfig
from sentinellayer.agent.detection.reputation_engine import ReputationEngine
from sentinellayer.agent.detection.yara_engine import YaraEngine
from sentinellayer.agent.monitors.usb_monitor import USBEvent, USBMonitor
from sentinellayer.agent.storage.db import LocalDatabase


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="defenceiq_usb_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_usb_event_serialization():
    """Verifies that USBEvent initializes correctly and serializes to dictionary."""
    ev = USBEvent(
        event_type="AUTORUN_DETECTED",
        drive_path="E:\\",
        volume_name="KINGSTON",
        device_id="E:\\",
        signals=["usb_device_inserted", "usb_autorun_detected"],
        metadata={"autorun_target": "payload.exe"},
    )
    d = ev.to_dict()
    assert d["event_type"] == "AUTORUN_DETECTED"
    assert d["drive_path"] == "E:\\"
    assert d["volume_name"] == "KINGSTON"
    assert "usb_autorun_detected" in d["signals"]
    assert d["metadata"]["autorun_target"] == "payload.exe"
    assert "event_id" in d
    assert "timestamp" in d


def test_check_autorun_detection(temp_dir):
    """Verifies parsing of benign and malicious autorun.inf files."""
    monitor = USBMonitor()

    # Case 1: No autorun.inf
    assert monitor.check_autorun(temp_dir) is None

    # Case 2: autorun.inf with open command
    autorun_file = os.path.join(temp_dir, "autorun.inf")
    with open(autorun_file, "w", encoding="utf-8") as f:
        f.write("[AutoRun]\nopen=setup.exe\naction=Start Setup\n")

    res = monitor.check_autorun(temp_dir)
    assert res is not None
    assert res["target_executable"] == "setup.exe"

    # Case 3: autorun.inf with shellexecute
    with open(autorun_file, "w", encoding="utf-8") as f:
        f.write("[AutoRun]\nshellexecute=script.vbs\n")

    res2 = monitor.check_autorun(temp_dir)
    assert res2 is not None
    assert res2["target_executable"] == "script.vbs"


def test_scan_drive_executables(temp_dir):
    """Verifies scanning for executable file extensions on a removable drive."""
    monitor = USBMonitor(config=USBMonitorConfig())

    # Create dummy files
    exe_file = os.path.join(temp_dir, "loader.exe")
    bat_file = os.path.join(temp_dir, "run.bat")
    txt_file = os.path.join(temp_dir, "notes.txt")

    for p in (exe_file, bat_file, txt_file):
        with open(p, "w") as f:
            f.write("test content")

    executables = monitor.scan_drive_executables(temp_dir)
    names = [e["filename"] for e in executables]
    assert "loader.exe" in names
    assert "run.bat" in names
    assert "notes.txt" not in names


def test_scan_drive_with_yara_and_reputation(temp_dir):
    """Verifies that detection engines flag suspicious content on USB drives."""
    yara_eng = YaraEngine()
    rep_eng = ReputationEngine()

    # Add hash to bad cache
    rep_eng.add_known_bad("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")  # empty file hash

    monitor = USBMonitor(
        yara_engine=yara_eng,
        reputation_engine=rep_eng,
    )

    # 1. File matching malicious hash
    bad_hash_file = os.path.join(temp_dir, "bad_known.exe")
    with open(bad_hash_file, "wb") as f:
        pass  # 0 bytes -> matches empty file hash

    # 2. File matching YARA rule (PowerShell bypass)
    yara_file = os.path.join(temp_dir, "dropper.ps1")
    with open(yara_file, "w") as f:
        f.write("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command calc.exe")

    executables = monitor.scan_drive_executables(temp_dir)
    by_name = {e["filename"]: e for e in executables}

    assert "bad_known.exe" in by_name
    assert "known_malicious_hash" in by_name["bad_known.exe"]["signals"]

    assert "dropper.ps1" in by_name
    assert "yara_rule_matched" in by_name["dropper.ps1"]["signals"]


def test_inspect_drive_full_flow(temp_dir):
    """Verifies inspect_drive produces complete USBEvent with all aggregated signals."""
    monitor = USBMonitor()

    # Add autorun and executable
    autorun_file = os.path.join(temp_dir, "autorun.inf")
    with open(autorun_file, "w") as f:
        f.write("[AutoRun]\nopen=installer.exe\n")

    exe_file = os.path.join(temp_dir, "installer.exe")
    with open(exe_file, "w") as f:
        f.write("Binary content")

    event = monitor.inspect_drive(temp_dir)
    assert event.event_type == "AUTORUN_DETECTED"
    assert "usb_device_inserted" in event.signals
    assert "usb_autorun_detected" in event.signals
    assert "created_persistence_autorun" in event.signals
    assert "usb_executable_present" in event.signals
    assert "autorun" in event.metadata
    assert "executables" in event.metadata


def test_correlator_and_scoring_handles_usb_threat(temp_dir):
    """Verifies that EventCorrelator and RiskScoringEngine handle USB threat events."""
    scoring = RiskScoringEngine()
    correlator = EventCorrelator(scoring_engine=scoring)

    usb_event = USBEvent(
        event_type="AUTORUN_DETECTED",
        drive_path="F:\\",
        volume_name="USB_DRIVE",
        signals=["usb_device_inserted", "usb_autorun_detected", "created_persistence_autorun", "usb_executable_present"],
        metadata={
            "autorun": {"path": "F:\\autorun.inf", "target_executable": "trojan.exe"},
            "executables": [{"path": "F:\\trojan.exe", "filename": "trojan.exe"}],
        },
    )

    incident = correlator.process_event(usb_event)
    assert incident is not None
    assert incident.root_process_name == "USB:USB_DRIVE"
    # Score: created_persistence_autorun (+20) + usb_executable_present (+15) = 35 [YELLOW]
    assert incident.score_result.score >= 35
    assert incident.score_result.band in ("YELLOW", "ORANGE", "RED")
    assert "F:\\autorun.inf" in incident.touched_files
    assert "F:\\trojan.exe" in incident.touched_files


def test_storage_persists_usb_event(temp_dir):
    """Verifies that LocalDatabase saves and indexes USBEvent."""
    db_file = os.path.join(temp_dir, "test.db")
    db = LocalDatabase(db_path=db_file)

    usb_event = USBEvent(
        event_type="DEVICE_INSERTED",
        drive_path="G:\\",
        volume_name="BACKUP",
        signals=["usb_device_inserted"],
    )

    ev_id = db.save_event(usb_event)
    assert ev_id == usb_event.event_id

    stats = db.get_system_stats()
    assert stats["total_events"] == 1

"""Unit tests for LocalDatabase SQLite storage and explainability persistence."""

import os
import tempfile
import pytest

from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.ai_engine.risk_scoring import ContributingSignal, ScoreResult
from sentinellayer.agent.monitors.process_monitor import ProcessEvent
from sentinellayer.agent.monitors.file_monitor import FileEvent
from sentinellayer.agent.monitors.network_monitor import NetworkEvent
from sentinellayer.agent.response.response_engine import ResponseActionRecord
from sentinellayer.agent.storage.db import LocalDatabase


@pytest.fixture
def temp_db():
    """Provides an isolated temporary SQLite database."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_defenceiq.db")
        db = LocalDatabase(db_path=db_path)
        yield db


def test_init_db_and_schema(temp_db):
    """Verify tables are created with proper schemas."""
    with temp_db._get_connection() as conn:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        ]
        assert "events" in tables
        assert "incidents" in tables
        assert "actions" in tables


def test_save_and_count_events(temp_db):
    """Verify persisting ProcessEvent, FileEvent, NetworkEvent."""
    p_ev = ProcessEvent(
        event_type="PROCESS_CREATED",
        pid=1001,
        name="test_proc.exe",
        signals=["spawned_script_shell"],
    )
    f_ev = FileEvent(
        event_type="FILE_CREATED",
        file_path="C:\\sample.dll",
        file_name="sample.dll",
        signals=["new_executable_file"],
    )
    n_ev = NetworkEvent(
        event_type="CONNECTION_ESTABLISHED",
        pid=1001,
        remote_address="93.184.216.34:443",
        signals=["connected_unrecognized_host"],
    )

    id1 = temp_db.save_event(p_ev)
    id2 = temp_db.save_event(f_ev)
    id3 = temp_db.save_event(n_ev)

    assert id1 == p_ev.event_id
    assert id2 == f_ev.event_id
    assert id3 == n_ev.event_id

    stats = temp_db.get_system_stats()
    assert stats["total_events"] == 3


def test_save_and_retrieve_incident_with_explainability(temp_db):
    """Verify incident with full mathematical explainability breakdown is persisted."""
    contrib = [
        ContributingSignal(
            name="spawned_script_shell",
            weight=20,
            category="EXECUTION",
            description="Process executed PowerShell",
        ),
        ContributingSignal(
            name="connected_unrecognized_host",
            weight=15,
            category="NETWORK",
            description="Outbound connection to public IP",
        ),
    ]
    explanation_text = "Assigned score 35/100 (YELLOW): Process executed PowerShell (+20 pts) • Outbound connection to public IP (+15 pts)"

    score_res = ScoreResult(
        score=35,
        band="YELLOW",
        contributing_signals=contrib,
        explanation=explanation_text,
    )

    inc = Incident(
        root_pid=7000,
        root_process_name="launcher.exe",
        involved_pids=[7000, 7001],
        touched_files=["C:\\temp\\dropper.exe"],
        network_destinations=["93.184.216.34:443"],
        signals=["spawned_script_shell", "connected_unrecognized_host"],
        score_result=score_res,
        status="OPEN",
    )

    inc_id = temp_db.save_incident(inc)
    assert inc_id == inc.incident_id

    retrieved = temp_db.get_incident(inc_id)
    assert retrieved is not None
    assert retrieved["incident_id"] == inc.incident_id
    assert retrieved["root_pid"] == 7000
    assert retrieved["risk_score"] == 35
    assert retrieved["risk_band"] == "YELLOW"
    assert retrieved["explanation"] == explanation_text
    assert len(retrieved["contributing_signals"]) == 2
    assert retrieved["contributing_signals"][0]["name"] == "spawned_script_shell"
    assert retrieved["contributing_signals"][0]["weight"] == 20
    assert 7001 in retrieved["involved_pids"]


def test_filter_recent_incidents_by_band(temp_db):
    """Verify filtering recent incidents by minimum risk band."""
    for i, band in enumerate(["GREEN", "YELLOW", "ORANGE", "RED"]):
        inc = Incident(
            root_pid=100 + i,
            root_process_name=f"proc_{band}.exe",
            score_result=ScoreResult(score=i * 30, band=band, contributing_signals=[], explanation=""),
        )
        temp_db.save_incident(inc)

    # All incidents
    all_inc = temp_db.get_recent_incidents(limit=10)
    assert len(all_inc) == 4

    # Min band ORANGE (should return ORANGE and RED)
    orange_up = temp_db.get_recent_incidents(limit=10, min_band="ORANGE")
    assert len(orange_up) == 2
    bands = [x["risk_band"] for x in orange_up]
    assert "ORANGE" in bands
    assert "RED" in bands


def test_save_and_retrieve_containment_actions(temp_db):
    """Verify containment action audit logging and incident resolution."""
    action = ResponseActionRecord(
        action_id="act_001",
        incident_id="inc_xyz",
        action_type="BLOCK_NETWORK",
        target="C:\\Windows\\System32\\bad.exe",
        success=True,
        rollback_handler="unblock_process('rule_123')",
        details={"rule_name": "rule_123"},
    )

    temp_db.save_action(action)
    actions = temp_db.get_incident_actions("inc_xyz")
    assert len(actions) == 1
    assert actions[0]["action_type"] == "BLOCK_NETWORK"
    assert actions[0]["rollback_handler"] == "unblock_process('rule_123')"
    assert actions[0]["details"]["rule_name"] == "rule_123"

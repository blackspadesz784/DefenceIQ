"""Unit tests for RiskScoringEngine and EventCorrelator."""

import time
import pytest

from sentinellayer.agent.ai_engine.event_correlator import EventCorrelator, Incident
from sentinellayer.agent.ai_engine.risk_scoring import RiskScoringEngine
from sentinellayer.agent.config.settings import Settings
from sentinellayer.agent.monitors.process_monitor import ProcessEvent
from sentinellayer.agent.monitors.file_monitor import FileEvent
from sentinellayer.agent.monitors.network_monitor import NetworkEvent


# ============================================================================
# Risk Scoring Tests
# ============================================================================
def test_additive_scoring_exact_weights():
    """Verify exact point weights matching the project specification."""
    engine = RiskScoringEngine()

    # Individual signal weight checks
    assert engine.get_signal_weight("unknown_unsigned_publisher") == 15
    assert engine.get_signal_weight("no_valid_digital_signature") == 10
    assert engine.get_signal_weight("spawned_script_shell") == 20
    assert engine.get_signal_weight("created_persistence_autorun") == 20
    assert engine.get_signal_weight("connected_unrecognized_host") == 15
    assert engine.get_signal_weight("modified_encrypted_many_files") == 20
    assert engine.get_signal_weight("attempted_disable_security") == 25


def test_score_bands_and_clamping():
    """Verify score bands: 0-30 Green, 31-60 Yellow, 61-80 Orange, 81-100 Red."""
    engine = RiskScoringEngine()

    # Empty signals -> 0 (GREEN)
    res_clean = engine.calculate_score([])
    assert res_clean.score == 0
    assert res_clean.band == "GREEN"

    # 15 + 10 = 25 -> GREEN (<= 30)
    res_green = engine.calculate_score(["unknown_unsigned_publisher", "no_valid_digital_signature"])
    assert res_green.score == 25
    assert res_green.band == "GREEN"

    # 25 + 20 = 45 -> YELLOW (31–60)
    res_yellow = engine.calculate_score([
        "unknown_unsigned_publisher",
        "no_valid_digital_signature",
        "spawned_script_shell",
    ])
    assert res_yellow.score == 45
    assert res_yellow.band == "YELLOW"

    # 45 + 20 + 15 = 80 -> ORANGE (61–80)
    res_orange = engine.calculate_score([
        "unknown_unsigned_publisher",
        "no_valid_digital_signature",
        "spawned_script_shell",
        "created_persistence_autorun",
        "connected_unrecognized_host",
    ])
    assert res_orange.score == 80
    assert res_orange.band == "ORANGE"

    # 80 + 25 = 105 -> clamped to 100, RED (81–100)
    res_red = engine.calculate_score([
        "unknown_unsigned_publisher",
        "no_valid_digital_signature",
        "spawned_script_shell",
        "created_persistence_autorun",
        "connected_unrecognized_host",
        "attempted_disable_security",
    ])
    assert res_red.score == 100
    assert res_red.band == "RED"


def test_explainability_structure():
    """Verify explainability breakdown contains descriptions and formatted text."""
    engine = RiskScoringEngine()
    res = engine.calculate_score(["spawned_script_shell", "attempted_disable_security"])

    assert res.score == 45
    assert len(res.contributing_signals) == 2
    assert res.contributing_signals[0].name == "spawned_script_shell"
    assert res.contributing_signals[0].weight == 20
    assert res.contributing_signals[1].weight == 25

    # Explanation contains points and signal breakdown
    assert "Assigned score 45/100 (YELLOW)" in res.explanation
    assert "+20 pts" in res.explanation
    assert "+25 pts" in res.explanation


# ============================================================================
# Event Correlator Tests
# ============================================================================
def test_event_correlator_chains_multi_source_attack():
    """Verify incident escalates across process -> network -> file telemetry chain:

    unknown process -> spawns shell -> new network destination -> mass file encryption.
    """
    correlator = EventCorrelator()
    incidents_emitted: list[Incident] = []
    correlator.register_incident_callback(lambda inc: incidents_emitted.append(inc))

    # Step 1: Process Creation (unknown unsigned process)
    p_ev1 = ProcessEvent(
        event_type="PROCESS_CREATED",
        pid=5001,
        ppid=1000,
        name="dropper.exe",
        signals=["unknown_unsigned_publisher", "no_valid_digital_signature"],
    )
    inc1 = correlator.correlate_process_event(p_ev1)
    assert inc1.score_result.score == 25
    assert inc1.score_result.band == "GREEN"

    # Step 2: Dropper spawns PowerShell (child PID 5002)
    p_ev2 = ProcessEvent(
        event_type="PROCESS_CREATED",
        pid=5002,
        ppid=5001,  # child of 5001!
        name="powershell.exe",
        signals=["spawned_script_shell"],
    )
    inc2 = correlator.correlate_process_event(p_ev2)
    # Both 5001 and 5002 are in the same incident!
    assert 5001 in inc2.involved_pids
    assert 5002 in inc2.involved_pids
    # Score rises: 25 + 20 = 45 -> YELLOW
    assert inc2.score_result.score == 45
    assert inc2.score_result.band == "YELLOW"

    # Step 3: PowerShell connects to unrecognized external C2 host
    net_ev = NetworkEvent(
        event_type="CONNECTION_ESTABLISHED",
        pid=5002,
        process_name="powershell.exe",
        remote_address="198.51.100.99:4444",
        remote_ip="198.51.100.99",
        remote_port=4444,
        signals=["connected_unrecognized_host"],
    )
    inc3 = correlator.correlate_network_event(net_ev)
    assert inc3 is not None
    # Score rises: 45 + 15 = 60 -> YELLOW (at border of ORANGE)
    assert inc3.score_result.score == 60
    assert "198.51.100.99:4444" in inc3.network_destinations

    # Step 4: Rapid mass file encryption triggered
    file_ev = FileEvent(
        event_type="FILE_MODIFIED",
        file_path="C:\\Users\\Victim\\Documents\\finances.xlsx.enc",
        file_name="finances.xlsx.enc",
        entropy=7.8,
        signals=["modified_encrypted_many_files"],
    )
    inc4 = correlator.correlate_file_event(file_ev)
    assert inc4 is not None
    # Score rises: 60 + 20 = 80 -> ORANGE
    assert inc4.score_result.score == 80
    assert inc4.score_result.band == "ORANGE"
    assert "C:\\Users\\Victim\\Documents\\finances.xlsx.enc" in inc4.touched_files

    # Step 5: Process attempts to disable security
    p_ev3 = ProcessEvent(
        event_type="PROCESS_SPIKE",
        pid=5002,
        name="powershell.exe",
        signals=["attempted_disable_security"],
    )
    inc5 = correlator.correlate_process_event(p_ev3)
    # Score rises: 80 + 25 = 105 -> clamped to 100 -> RED
    assert inc5.score_result.score == 100
    assert inc5.score_result.band == "RED"
    assert "attempted_disable_security" in inc5.signals


def test_event_correlator_pruning():
    """Verify stale clean contexts older than window are pruned."""
    correlator = EventCorrelator(window_seconds=1.0)

    p_ev = ProcessEvent(
        event_type="PROCESS_CREATED",
        pid=9999,
        name="clean_proc.exe",
        signals=[],
    )
    correlator.correlate_process_event(p_ev)
    assert 9999 in correlator._pid_to_context

    # Wait for window to expire
    time.sleep(1.1)
    correlator.prune_stale_contexts()
    assert 9999 not in correlator._pid_to_context

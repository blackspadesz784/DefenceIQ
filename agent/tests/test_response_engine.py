"""Unit tests for ResponseEngine, FirewallController, ProcessController, and QuarantineManager."""

import os
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.ai_engine.risk_scoring import ScoreResult
from sentinellayer.agent.config.settings import ProtectionLevel, Settings
from sentinellayer.agent.response.firewall_controller import FirewallController
from sentinellayer.agent.response.process_controller import ProcessController
from sentinellayer.agent.response.quarantine import QuarantineManager
from sentinellayer.agent.response.response_engine import ResponseEngine


# ============================================================================
# Quarantine Manager Tests
# ============================================================================
def test_quarantine_and_restore_cycle():
    """Verify complete, non-destructive file quarantine and restoration cycle."""
    with tempfile.TemporaryDirectory() as vault_dir:
        qm = QuarantineManager(quarantine_dir=vault_dir)

        # Create a test file
        with tempfile.NamedTemporaryFile(delete=False) as orig:
            orig.write(b"Benign simulated payload content to quarantine")
            orig_path = orig.name

        try:
            # 1. Quarantine file
            res = qm.quarantine_file(orig_path, reason="Test quarantine", signals=["yara_rule_matched"])
            assert res["success"] is True
            qid = res["quarantine_id"]

            # Original path must no longer exist
            assert not os.path.exists(orig_path)

            # Vault must contain the .qf and .json files
            vault_file = os.path.join(vault_dir, f"{qid}.qf")
            meta_file = os.path.join(vault_dir, f"{qid}.json")
            assert os.path.isfile(vault_file)
            assert os.path.isfile(meta_file)

            # 2. Restore file
            restored = qm.restore_file(qid)
            assert restored is True
            assert os.path.isfile(orig_path)

            # Check content preserved
            with open(orig_path, "rb") as f:
                assert f.read() == b"Benign simulated payload content to quarantine"
        finally:
            if os.path.exists(orig_path):
                try:
                    os.remove(orig_path)
                except OSError:
                    pass


# ============================================================================
# Firewall Controller Tests
# ============================================================================
def test_firewall_block_and_rollback_dry_run():
    """Verify firewall block rule registration and rollback in dry-run mode."""
    fc = FirewallController(dry_run=True)

    prog_path = "C:\\Windows\\System32\\suspicious_tool.exe"
    res = fc.block_process(prog_path)

    assert res["success"] is True
    rule_name = res["rule_name"]
    assert rule_name in fc.active_rules
    assert fc.active_rules[rule_name].program_path == prog_path

    # Rollback single rule
    unblocked = fc.unblock_process(rule_name)
    assert unblocked is True
    assert rule_name not in fc.active_rules


# ============================================================================
# Process Controller Tests
# ============================================================================
def test_process_suspension_and_resumption():
    """Verify process suspension and resumption logic using mocked psutil."""
    pc = ProcessController()
    mock_proc = MagicMock()
    mock_proc.pid = 4321
    mock_proc.name.return_value = "trojan.exe"
    mock_proc.exe.return_value = "C:\\trojan.exe"

    with patch("psutil.Process", return_value=mock_proc):
        # 1. Suspend
        res = pc.suspend_process(4321)
        assert res["success"] is True
        assert 4321 in pc.suspended_processes
        mock_proc.suspend.assert_called_once()

        # 2. Resume
        resumed = pc.resume_process(4321)
        assert resumed is True
        assert 4321 not in pc.suspended_processes
        mock_proc.resume.assert_called_once()


# ============================================================================
# Graduated Response Engine Tests
# ============================================================================
def test_response_engine_graduated_actions():
    """Verify graduated actions across GREEN, YELLOW, ORANGE, RED bands."""
    with tempfile.TemporaryDirectory() as vault_dir:
        qm = QuarantineManager(quarantine_dir=vault_dir)
        fc = FirewallController(dry_run=True)
        pc = ProcessController()
        re = ResponseEngine(firewall_controller=fc, process_controller=pc, quarantine_manager=qm)

        # 1. GREEN Incident -> LOG only
        inc_green = Incident(
            root_pid=100,
            root_process_name="normal.exe",
            score_result=ScoreResult(score=10, band="GREEN", contributing_signals=[], explanation="Clean"),
        )
        actions_green = re.handle_incident(inc_green)
        assert len(actions_green) == 1
        assert actions_green[0].action_type == "LOG"

        # 2. YELLOW Incident -> NOTIFY only
        inc_yellow = Incident(
            root_pid=200,
            root_process_name="curious.exe",
            score_result=ScoreResult(score=40, band="YELLOW", contributing_signals=[], explanation="Suspicious"),
        )
        actions_yellow = re.handle_incident(inc_yellow)
        assert any(a.action_type == "NOTIFY" for a in actions_yellow)
        assert not any(a.action_type == "BLOCK_NETWORK" for a in actions_yellow)

        # 3. ORANGE Incident -> NOTIFY + BLOCK_NETWORK + SUSPEND
        mock_proc = MagicMock()
        mock_proc.pid = 300
        mock_proc.exe.return_value = "C:\\bad_network.exe"
        with patch("psutil.Process", return_value=mock_proc):
            inc_orange = Incident(
                root_pid=300,
                involved_pids=[300],
                root_process_name="bad_network.exe",
                score_result=ScoreResult(score=70, band="ORANGE", contributing_signals=[], explanation="High Risk"),
            )
            actions_orange = re.handle_incident(inc_orange)
            types = [a.action_type for a in actions_orange]
            assert "BLOCK_NETWORK" in types
            assert "SUSPEND" in types

        # 4. RED Incident -> BLOCK_NETWORK + SUSPEND + ISOLATE + QUARANTINE
        with tempfile.NamedTemporaryFile(delete=False) as target_file:
            target_file.write(b"malicious sample payload")
            t_path = target_file.name

        try:
            mock_proc2 = MagicMock()
            mock_proc2.pid = 400
            mock_proc2.exe.return_value = t_path
            mock_proc2.children.return_value = []

            with patch("psutil.Process", return_value=mock_proc2):
                inc_red = Incident(
                    root_pid=400,
                    involved_pids=[400],
                    root_process_name="ransomware.exe",
                    touched_files=[t_path],
                    score_result=ScoreResult(score=95, band="RED", contributing_signals=[], explanation="Critical Threat"),
                )
                actions_red = re.handle_incident(inc_red)
                types_red = [a.action_type for a in actions_red]
                assert "BLOCK_NETWORK" in types_red
                assert "SUSPEND" in types_red
                assert "ISOLATE" in types_red
                assert "QUARANTINE" in types_red
                assert not os.path.exists(t_path)

                # 5. Rollback RED incident
                rollback_res = re.rollback_incident(inc_red.incident_id)
                assert len(rollback_res["restored_files"]) == 1
                assert os.path.exists(t_path)
        finally:
            if os.path.exists(t_path):
                os.remove(t_path)

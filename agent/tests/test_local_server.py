"""Unit and integration tests for DefenceIQ Local Server (REST and WebSockets)."""

import os
import shutil
import tempfile
import time
import pytest
from starlette.testclient import TestClient

from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.ai_engine.risk_scoring import ScoreResult, ContributingSignal
from sentinellayer.agent.config.settings import ProtectionLevel, Settings
from sentinellayer.agent.comms.local_server import LocalServer
from sentinellayer.agent.response.firewall_controller import FirewallController
from sentinellayer.agent.response.process_controller import ProcessController
from sentinellayer.agent.response.quarantine import QuarantineManager
from sentinellayer.agent.response.response_engine import ResponseActionRecord, ResponseEngine
from sentinellayer.agent.storage.db import LocalDatabase


@pytest.fixture
def temp_env():
    """Provides an isolated directory for database and pairing token testing."""
    temp_dir = tempfile.mkdtemp(prefix="defenceiq_server_test_")
    db_path = os.path.join(temp_dir, "test_defenceiq.db")
    token_path = os.path.join(temp_dir, "test_token.key")
    vault_path = os.path.join(temp_dir, "quarantine_vault")

    settings = Settings(
        db_path=db_path,
        pairing_token_file=token_path,
        protection_level=ProtectionLevel.BALANCED,
    )
    db = LocalDatabase(db_path=db_path)
    fw = FirewallController(dry_run=True)
    pm = ProcessController()
    qm = QuarantineManager(quarantine_dir=vault_path)
    resp = ResponseEngine(
        settings=settings,
        firewall_controller=fw,
        process_controller=pm,
        quarantine_manager=qm,
    )

    server = LocalServer(
        host="127.0.0.1",
        port=8999,
        settings=settings,
        db=db,
        response_engine=resp,
        pairing_token="TEST_PAIRING_123",
    )
    client = TestClient(server.app)

    yield {
        "temp_dir": temp_dir,
        "settings": settings,
        "db": db,
        "response_engine": resp,
        "server": server,
        "client": client,
        "token": "TEST_PAIRING_123",
    }

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_pairing_token_lifecycle(temp_env):
    """Verifies token verification and file-based token generation."""
    server = temp_env["server"]
    token = temp_env["token"]

    assert server.verify_token(token) is True
    assert server.verify_token(token.lower()) is True  # Case insensitive
    assert server.verify_token(f"  {token}  ") is True  # Whitespace tolerant
    assert server.verify_token("WRONG_TOKEN") is False
    assert server.verify_token("") is False
    assert server.verify_token(None) is False

    # Test auto-generation if not supplied
    fresh_token_file = os.path.join(temp_env["temp_dir"], "fresh.key")
    settings = Settings(pairing_token_file=fresh_token_file)
    gen_server = LocalServer(settings=settings)
    assert len(gen_server.pairing_token) == 8
    assert os.path.isfile(fresh_token_file)


def test_health_and_pairing_endpoints(temp_env):
    """Verifies unauthenticated health check and pairing handshake."""
    client = temp_env["client"]
    token = temp_env["token"]

    # Health check requires no auth
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "ok"

    # Pair with invalid token
    bad_pair = client.post("/pair", json={"token": "INVALID_TOKEN"})
    assert bad_pair.status_code == 401

    # Pair with valid token
    good_pair = client.post("/pair", json={"token": token})
    assert good_pair.status_code == 200
    assert good_pair.json()["success"] is True
    assert "lan_ip" in good_pair.json()
    assert good_pair.json()["protection_level"] == "balanced"


def test_authentication_methods(temp_env):
    """Verifies Bearer header, X-Pairing-Token header, and query parameter auth."""
    client = temp_env["client"]
    token = temp_env["token"]

    # 1. No auth -> 401
    assert client.get("/status").status_code == 401

    # 2. Invalid auth -> 401
    assert client.get("/status", headers={"Authorization": "Bearer BAD"}).status_code == 401

    # 3. Bearer Header -> 200
    r1 = client.get("/status", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200

    # 4. X-Pairing-Token Header -> 200
    r2 = client.get("/status", headers={"X-Pairing-Token": token})
    assert r2.status_code == 200

    # 5. Query parameter -> 200
    r3 = client.get(f"/status?token={token}")
    assert r3.status_code == 200


def test_status_endpoint_payload(temp_env):
    """Verifies detailed payload returned by /status."""
    client = temp_env["client"]
    token = temp_env["token"]

    resp = client.get("/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()

    assert data["health_state"] in ("SECURE", "WARNING", "ELEVATED_RISK", "CRITICAL_THREAT")
    assert data["protection_level"] == "balanced"
    assert "stats" in data
    assert "engines" in data
    assert data["engines"]["static_analysis"] == "ready"
    assert data["engines"]["yara_engine"] == "ready"


def test_incidents_crud_and_explainability(temp_env):
    """Verifies retrieval of incidents with explainable breakdown and resolution."""
    client = temp_env["client"]
    db = temp_env["db"]
    token = temp_env["token"]

    # Insert test incident
    score_res = ScoreResult(
        score=75,
        band="ORANGE",
        contributing_signals=[
            ContributingSignal(
                name="spawned_script_shell",
                weight=20,
                category="PROCESS",
                description="Suspicious shell execution",
            ),
            ContributingSignal(
                name="modified_encrypted_many_files",
                weight=20,
                category="FILE",
                description="Rapid file modification burst",
            ),
        ],
        explanation="Process spawned script shell and encrypted multiple files.",
    )
    inc = Incident(
        incident_id="inc_test_001",
        root_pid=9999,
        root_process_name="malicious_sample.exe",
        involved_pids={9999, 10001},
        touched_files={"C:\\test\\doc1.enc"},
        network_destinations={"198.51.100.1"},
        signals=["spawned_script_shell", "modified_encrypted_many_files"],
        score_result=score_res,
        status="OPEN",
    )
    db.save_incident(inc)

    # 1. GET /incidents
    r = client.get("/incidents", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["count"] >= 1
    found = [i for i in r.json()["incidents"] if i["incident_id"] == "inc_test_001"][0]
    assert found["risk_score"] == 75
    assert found["risk_band"] == "ORANGE"
    assert len(found["contributing_signals"]) == 2
    assert "explanation" in found

    # 2. GET /incidents/{id}
    single_r = client.get("/incidents/inc_test_001", headers={"Authorization": f"Bearer {token}"})
    assert single_r.status_code == 200
    assert single_r.json()["incident_id"] == "inc_test_001"
    assert "actions" in single_r.json()

    # 3. POST /incidents/{id}/resolve
    res_r = client.post("/incidents/inc_test_001/resolve", headers={"Authorization": f"Bearer {token}"})
    assert res_r.status_code == 200
    assert res_r.json()["status"] == "RESOLVED"

    # Verify status in DB
    updated = db.get_incident("inc_test_001")
    assert updated["status"] == "RESOLVED"


def test_incident_rollback(temp_env):
    """Verifies that calling rollback reverses containment actions and updates incident status."""
    client = temp_env["client"]
    db = temp_env["db"]
    resp_engine = temp_env["response_engine"]
    token = temp_env["token"]

    inc_id = "inc_rollback_999"
    inc = Incident(
        incident_id=inc_id,
        root_pid=8888,
        root_process_name="ransom_test.exe",
        involved_pids={8888},
        status="CONTAINED",
    )
    db.save_incident(inc)

    # Create dummy containment action in response engine
    resp_engine.incident_actions[inc_id] = [
        ResponseActionRecord(
            action_id="act_block_1",
            incident_id=inc_id,
            action_type="BLOCK_NETWORK",
            target="ransom_test.exe",
            details={"rule_name": "DefenceIQ_Block_ransom_test.exe"},
        )
    ]

    # POST /incidents/{id}/rollback
    rb_resp = client.post(f"/incidents/{inc_id}/rollback", headers={"Authorization": f"Bearer {token}"})
    assert rb_resp.status_code == 200
    data = rb_resp.json()
    assert data["success"] is True
    assert data["status"] == "ROLLED_BACK"
    assert "unblocked_rules" in data["results"]

    # Verify status in DB is ROLLED_BACK
    updated_inc = db.get_incident(inc_id)
    assert updated_inc["status"] == "ROLLED_BACK"


def test_protection_level_update(temp_env):
    """Verifies updating agent protection level."""
    client = temp_env["client"]
    token = temp_env["token"]
    settings = temp_env["settings"]

    # Valid change to maximum
    r1 = client.post(
        "/protection/level",
        json={"level": "maximum"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 200
    assert r1.json()["protection_level"] == "maximum"
    assert settings.protection_level == ProtectionLevel.MAXIMUM

    # Valid change to basic
    r2 = client.post(
        "/protection/level",
        json={"level": "basic"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 200
    assert r2.json()["protection_level"] == "basic"
    assert settings.protection_level == ProtectionLevel.BASIC

    # Invalid level
    r3 = client.post(
        "/protection/level",
        json={"level": "invalid_mode"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r3.status_code == 400


def test_quarantine_vault_operations(temp_env):
    """Verifies listing and restoring quarantined files via API."""
    client = temp_env["client"]
    resp_engine = temp_env["response_engine"]
    token = temp_env["token"]
    temp_dir = temp_env["temp_dir"]

    # Create dummy file to quarantine
    sample_file = os.path.join(temp_dir, "suspicious.exe")
    with open(sample_file, "w") as f:
        f.write("Suspicious test payload")

    # Quarantine file
    q_res = resp_engine.quarantine.quarantine_file(sample_file, reason="Unit test")
    assert q_res["success"] is True
    qid = q_res["quarantine_id"]

    # 1. GET /quarantine
    q_list = client.get("/quarantine", headers={"Authorization": f"Bearer {token}"})
    assert q_list.status_code == 200
    assert q_list.json()["count"] >= 1
    assert any(f["quarantine_id"] == qid for f in q_list.json()["quarantined_files"])

    # 2. POST /quarantine/{id}/restore
    restore_resp = client.post(f"/quarantine/{qid}/restore", headers={"Authorization": f"Bearer {token}"})
    assert restore_resp.status_code == 200
    assert restore_resp.json()["status"] == "RESTORED"
    assert os.path.isfile(sample_file)


def test_websocket_stream_and_broadcast(temp_env):
    """Verifies WebSocket real-time alerts stream connection and broadcast handling."""
    client = temp_env["client"]
    server = temp_env["server"]
    token = temp_env["token"]

    # 1. Unauthorized connection should close immediately
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/alerts?token=WRONG"):
            pass

    # 2. Authorized connection receives initial welcome frame
    with client.websocket_connect(f"/ws/alerts?token={token}") as ws:
        init_frame = ws.receive_json()
        assert init_frame["type"] == "connected"
        assert "lan_ip" in init_frame
        assert init_frame["protection_level"] == "balanced"

        # 3. Test ping / pong
        ws.send_json({"type": "ping"})
        pong_frame = ws.receive_json()
        assert pong_frame["type"] == "pong"

        # 4. Test broadcast delivery
        import asyncio
        asyncio.run(server.broadcast_event("PROCESS", "PROCESS_SPAWN", "Test spawn", ["suspicious_process_name"]))
        broadcast_frame = ws.receive_json()
        assert broadcast_frame["type"] == "telemetry_event"
        assert broadcast_frame["domain"] == "PROCESS"
        assert "suspicious_process_name" in broadcast_frame["signals"]

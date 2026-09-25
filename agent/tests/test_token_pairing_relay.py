"""Tests for DefenceIQ Token-Based Device Pairing, Relay Protocol & Privacy Guarantees."""

import json
from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from sentinellayer.agent.comms.cloud_relay import (
    CloudRelay,
    DeviceIdentification,
    derive_relay_channels,
    sign_payload,
    verify_payload_signature,
)
from sentinellayer.agent.comms.local_server import LocalServer
from sentinellayer.agent.config.settings import default_settings


def test_derive_relay_channels():
    t1 = "DIQ-8K2A-9X1B"
    t2 = "diq8k2a9x1b"
    ch1 = derive_relay_channels(t1)
    ch2 = derive_relay_channels(t2)

    assert ch1["downlink_topic"] == ch2["downlink_topic"]
    assert ch1["uplink_topic"] == ch2["uplink_topic"]
    assert ch1["auth_secret"] == ch2["auth_secret"]
    assert ch1["downlink_topic"].startswith("diq_down_")
    assert ch1["uplink_topic"].startswith("diq_up_")
    assert len(ch1["auth_secret"]) == 64  # SHA256 hex


def test_sign_and_verify_payload():
    secret = "test_super_secret_key_12345"
    payload = {
        "device_id": "LAPTOP-01",
        "threat": "Ransomware Alert",
        "score": 90,
        "files": ["test.docx"],
    }
    sig = sign_payload(payload, secret)
    assert isinstance(sig, str) and len(sig) == 64

    # Valid verification
    assert verify_payload_signature(payload, sig, secret) is True

    # Tampered payload must fail verification
    tampered = dict(payload)
    tampered["score"] = 0
    assert verify_payload_signature(tampered, sig, secret) is False

    # Wrong secret must fail
    assert verify_payload_signature(payload, sig, "wrong_secret") is False


def test_device_identification_local():
    dev = DeviceIdentification.create_local()
    assert dev.device_id.startswith("LAPTOP-")
    assert len(dev.hostname) > 0
    assert len(dev.authorized_paths) >= 1
    assert dev.protection_level in ("basic", "balanced", "maximum")


def test_publish_handshake_and_threat_alert():
    relay = CloudRelay(pairing_token="DIQ-TEST-TOKEN", enabled=True)

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        # 1. Publish handshake
        ok_handshake = relay.publish_handshake()
        assert ok_handshake is True
        assert mock_urlopen.called

        # Verify sent payload envelope
        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["type"] == "PAIR_HANDSHAKE"
        assert sent_body["v"] == 2
        assert "hmac" in sent_body
        assert "privacy_guarantee" in sent_body["data"]

        # 2. Publish threat alert
        incident = {
            "incident_id": "INC-8899",
            "risk_score": 95,
            "risk_band": "RED",
            "root_process_name": "malware.exe",
            "signals": ["modified_encrypted_many_files", "rapid_file_modifications"],
            "touched_files": [r"C:\Users\DELL\Documents\confidential.pdf"],
            "status": "CONTAINED",
            "explanation": "Mass ransomware encryption behavior detected.",
        }
        ok_alert = relay.publish_threat_alert(incident)
        assert ok_alert is True

        req2 = mock_urlopen.call_args[0][0]
        alert_body = json.loads(req2.data.decode("utf-8"))
        assert alert_body["type"] == "THREAT_ALERT"
        alert_data = alert_body["data"]
        assert alert_data["severity"] == "RED"
        assert alert_data["risk_score"] == 95
        assert alert_data["threat_type"] == "Potential Ransomware Activity"
        # Confirm least privilege: only basename is sent, never full path or content
        assert "confidential.pdf" in alert_data["affected_files"]
        assert r"C:\Users\DELL" not in alert_data["affected_files"][0]


def test_server_pair_mobile_and_monitoring_scope(tmp_path):
    token_file = str(tmp_path / "pairing_token.key")
    db_file = str(tmp_path / "test.db")

    server = LocalServer(
        host="127.0.0.1",
        port=8765,
        settings=default_settings,
        pairing_token="ORIGINAL_TOKEN",
    )
    server.pairing_token_file = token_file
    client = TestClient(server.app)

    # 1. Test GET /monitoring-scope (unauthenticated, public policy endpoint)
    res_scope = client.get("/monitoring-scope")
    assert res_scope.status_code == 200
    scope_data = res_scope.json()
    assert "authorized_directories" in scope_data
    assert "privacy_guarantee" in scope_data
    assert "Least privilege" in scope_data["privacy_guarantee"]

    # 2. Test POST /pair-mobile with mobile token
    mobile_token = "DIQ-99AA-BB88"
    res_pair = client.post("/pair-mobile", json={"token": mobile_token})
    assert res_pair.status_code == 200
    pair_data = res_pair.json()
    assert pair_data["success"] is True
    assert pair_data["token"] == mobile_token
    assert server.pairing_token == mobile_token

    # 3. Test POST /revoke-pairing
    res_revoke = client.post("/revoke-pairing")
    assert res_revoke.status_code == 200
    revoke_data = res_revoke.json()
    assert revoke_data["success"] is True
    assert revoke_data["new_token"] != mobile_token
    assert server.pairing_token == revoke_data["new_token"]

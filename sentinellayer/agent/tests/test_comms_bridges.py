"""Unit tests for DefenceIQ alternate communication bridges.

Tests USB ADB bridge, Cloud Relay (ntfy.sh), and Bluetooth Low Energy (BLE) bridge.
"""

import json
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from sentinellayer.agent.comms.usb_bridge import USBBridge
from sentinellayer.agent.comms.cloud_relay import CloudRelay
from sentinellayer.agent.comms.bluetooth_bridge import (
    BluetoothBridge,
    PacketAssembler,
    encode_frames,
    FRAME_TYPE_ALERT,
    FRAME_TYPE_STATUS,
    DEFENCEIQ_SERVICE_UUID,
)
from sentinellayer.agent.comms.local_server import LocalServer
from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.ai_engine.risk_scoring import ScoreResult, ContributingSignal


# ============================================================================
# 1. USBBridge Tests
# ============================================================================

def test_usb_bridge_init():
    bridge = USBBridge(local_port=8765, remote_port=8765)
    assert bridge.local_port == 8765
    assert bridge.remote_port == 8765
    status = bridge.get_status()
    assert "adb_available" in status
    assert "devices" in status
    assert "active_forwards" in status


def test_usb_bridge_is_available_mocked():
    bridge = USBBridge(adb_path="mock_adb.exe")
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Android Debug Bridge version 1.0.41\n")
        assert bridge.is_available() is True

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        assert bridge.is_available() is False


def test_usb_bridge_list_devices_parsing():
    bridge = USBBridge(adb_path="mock_adb.exe")
    adb_output = (
        "List of devices attached\n"
        "emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emulator64_arm64 transport_id:1\n"
        "RF8M123456            unauthorized usb:1-1 transport_id:2\n"
        "192.168.1.50:5555      offline transport_id:3\n"
    )
    with patch("sentinellayer.agent.comms.usb_bridge.USBBridge.is_available", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=adb_output)
            devices = bridge.list_devices()
            assert len(devices) == 3
            assert devices[0]["serial"] == "emulator-5554"
            assert devices[0]["state"] == "device"
            assert devices[0]["model"] == "sdk_gphone64_arm64"

            assert devices[1]["serial"] == "RF8M123456"
            assert devices[1]["state"] == "unauthorized"

            assert devices[2]["serial"] == "192.168.1.50:5555"
            assert devices[2]["state"] == "offline"


def test_usb_bridge_setup_and_remove_forward():
    bridge = USBBridge(adb_path="mock_adb.exe", local_port=8765, remote_port=8765)
    with patch("sentinellayer.agent.comms.usb_bridge.USBBridge.is_available", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            success = bridge.setup_forward(serial="emulator-5554")
            assert success is True
            assert any("tcp:8765 -> tcp:8765" in f for f in bridge._active_forwards)

            # Test remove
            removed = bridge.remove_forward(serial="emulator-5554")
            assert removed is True
            assert len(bridge._active_forwards) == 0


def test_usb_bridge_list_active_forwards():
    bridge = USBBridge(adb_path="mock_adb.exe")
    with patch("sentinellayer.agent.comms.usb_bridge.USBBridge.is_available", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="emulator-5554 tcp:8765 tcp:8765\n")
            forwards = bridge.list_active_forwards()
            assert len(forwards) == 1
            assert "tcp:8765 tcp:8765" in forwards[0]


# ============================================================================
# 2. CloudRelay Tests
# ============================================================================

def test_cloud_relay_topic_generation():
    # Deterministic topic from pairing token
    relay1 = CloudRelay(pairing_token="TESTTOKEN123")
    relay2 = CloudRelay(pairing_token="TESTTOKEN123")
    assert relay1.topic == relay2.topic
    assert relay1.topic.startswith("defenceiq_")

    # Explicit custom topic overrides
    relay_custom = CloudRelay(topic="my_custom_safe_channel")
    assert relay_custom.topic == "my_custom_safe_channel"


def test_cloud_relay_payload_formatting():
    relay = CloudRelay(enabled=False)

    red_incident = {
        "incident_id": "INC-RED-001",
        "process_name": "malicious_ransomware.exe",
        "risk_score": 85,
        "risk_band": "RED",
        "action_taken": "SUSPEND",
        "signals": ["rapid_file_modifications", "modified_encrypted_many_files"],
    }
    payload = relay.format_incident_payload(red_incident)
    assert payload["priority"] == "urgent"
    assert "85/100" in payload["title"]
    assert "rotating_light" in payload["tags"]
    assert "SUSPEND" in payload["message"]

    orange_incident = {
        "incident_id": "INC-ORG-002",
        "process_name": "powershell.exe",
        "risk_score": 55,
        "risk_band": "ORANGE",
        "action_taken": "NOTIFY",
        "signals": ["spawned_script_shell"],
    }
    payload_orange = relay.format_incident_payload(orange_incident)
    assert payload_orange["priority"] == "high"
    assert "55/100" in payload_orange["title"]


def test_cloud_relay_publish_disabled():
    relay = CloudRelay(enabled=False)
    # When disabled, should log locally and record in history without attempting network call
    res = relay.publish_alert(title="Test Alert", message="Test body")
    assert res is True
    history = relay.get_history()
    assert len(history) == 1
    assert history[0]["title"] == "Test Alert"


def test_cloud_relay_publish_enabled_mock_network():
    relay = CloudRelay(enabled=True, topic="test_topic")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = relay.publish_alert(title="Active Push", message="Breach prevented", priority="urgent")
        assert res is True
        assert mock_urlopen.called

        # Verify request parameters
        req = mock_urlopen.call_args[0][0]
        assert "test_topic" in req.full_url
        assert req.headers["Title"] == "Active Push"
        assert req.headers["Priority"] == "urgent"


# ============================================================================
# 3. BluetoothBridge Tests
# ============================================================================

def test_bluetooth_bridge_init():
    bt = BluetoothBridge()
    assert bt.service_uuid == DEFENCEIQ_SERVICE_UUID
    assert bt.is_ble_supported() is True
    status = bt.get_status()
    assert status["device_name"] == "DefenceIQ-Agent"
    assert status["service_uuid"] == DEFENCEIQ_SERVICE_UUID
    assert status["ble_supported"] is True


def test_ble_packet_framing_and_reassembly():
    # Large data payload requiring multiple MTU chunks
    payload_data = {
        "event": "alert",
        "incident_id": "INC-TEST-123",
        "score": 75,
        "details": "A" * 300,  # Ensure payload exceeds 128 bytes MTU
    }

    chunks = encode_frames(payload_data, frame_type=FRAME_TYPE_ALERT, msg_id=1, mtu=64)
    assert len(chunks) > 1  # Verify chunked into multiple frames

    # Reassemble using PacketAssembler
    assembler = PacketAssembler()
    result = None
    for chunk in chunks:
        result = assembler.feed_chunk(chunk)

    assert result is not None
    assert result["incident_id"] == "INC-TEST-123"
    assert result["score"] == 75
    assert len(result["details"]) == 300


def test_bluetooth_bridge_format_methods():
    bt = BluetoothBridge()
    status_chunks = bt.format_status_frames({"health": "GREEN", "active_threats": 0}, mtu=128)
    assert len(status_chunks) >= 1
    assert status_chunks[0][1] == FRAME_TYPE_STATUS

    alert_chunks = bt.format_alert_frames({"incident_id": "INC-01", "score": 80}, mtu=128)
    assert len(alert_chunks) >= 1
    assert alert_chunks[0][1] == FRAME_TYPE_ALERT


def test_bluetooth_bridge_command_dispatch():
    bt = BluetoothBridge()

    executed_command = None
    def mock_command_handler(cmd_dict):
        nonlocal executed_command
        executed_command = cmd_dict
        return {"success": True, "action": cmd_dict.get("action")}

    bt.register_command_handler(mock_command_handler)

    command_msg = {"command": "rollback", "incident_id": "INC-999"}
    chunks = encode_frames(command_msg, msg_id=42, mtu=128)
    assert len(chunks) == 1

    resp = bt.receive_chunk(chunks[0])
    assert resp is not None
    assert executed_command == command_msg
    assert resp["success"] is True


# ============================================================================
# 4. LocalServer Integration with Transports
# ============================================================================

def test_local_server_transports_endpoint(tmp_path):
    import asyncio
    from fastapi.testclient import TestClient

    db_path = str(tmp_path / "test_transports.db")
    token_path = str(tmp_path / "pairing_token.key")

    usb = USBBridge()
    cloud = CloudRelay(enabled=False)
    bt = BluetoothBridge()

    server = LocalServer(
        host="127.0.0.1",
        port=8765,
        pairing_token="SECRETPASS",
        usb_bridge=usb,
        cloud_relay=cloud,
        bluetooth_bridge=bt,
    )
    server.pairing_token_file = token_path

    client = TestClient(server.app)

    # 1. Without auth -> 401
    resp = client.get("/transports")
    assert resp.status_code == 401

    # 2. With auth -> 200 and full transport dictionary
    resp = client.get("/transports", headers={"Authorization": "Bearer SECRETPASS"})
    assert resp.status_code == 200
    data = resp.json()
    assert "lan" in data
    assert "usb" in data
    assert "bluetooth" in data
    assert "cloud" in data
    assert data["cloud"]["enabled"] is False
    assert data["bluetooth"]["ble_supported"] is True


def test_local_server_cloud_push_on_high_incident(tmp_path):
    import asyncio
    from unittest.mock import patch, MagicMock

    db_path = str(tmp_path / "test_cloud_push.db")
    cloud = CloudRelay(enabled=True)
    bt = BluetoothBridge()

    server = LocalServer(
        host="127.0.0.1",
        port=8765,
        pairing_token="SECRETPASS",
        cloud_relay=cloud,
        bluetooth_bridge=bt,
    )

    # Simulate an ORANGE/RED incident
    sig = ContributingSignal(
        name="rapid_file_modifications",
        weight=20,
        category="FILE",
        description="Mass modification",
    )
    incident = Incident(
        incident_id="INC-URGENT-99",
        created_at=1000.0,
        updated_at=1005.0,
        root_pid=1234,
        root_process_name="suspicious.exe",
        signals={"rapid_file_modifications"},
        score_result=ScoreResult(
            score=70,
            band="ORANGE",
            contributing_signals=[sig],
            explanation="High threat activity",
        ),
    )

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Broadcast incident via asyncio.run
        asyncio.run(server.broadcast_incident(incident))

    # Cloud relay should have recorded the alert
    history = cloud.get_history()
    assert len(history) == 1
    assert "HIGH RISK ALERT (70/100)" in history[0]["title"]
    assert history[0]["priority"] == "high"

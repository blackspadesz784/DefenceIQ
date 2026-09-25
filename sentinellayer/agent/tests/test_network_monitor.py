"""Unit tests for NetworkMonitor, NetworkEvent, and IP reputation checks."""

from collections import namedtuple
import json
import socket
from unittest.mock import MagicMock, patch
import pytest

from sentinellayer.agent.config.settings import NetworkMonitorConfig
from sentinellayer.agent.monitors.network_monitor import (
    NetworkEvent,
    NetworkMonitor,
    is_private_or_local_ip,
)

# Mock connection tuple matching psutil sconn
MockAddr = namedtuple("MockAddr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def test_network_event_serialization():
    """Verify NetworkEvent serializes to valid dict and JSON."""
    event = NetworkEvent(
        event_type="CONNECTION_ESTABLISHED",
        pid=1234,
        process_name="curl.exe",
        protocol="TCP",
        local_address="192.168.1.50:52000",
        remote_address="93.184.216.34:443",
        remote_ip="93.184.216.34",
        remote_port=443,
        status="ESTABLISHED",
        is_outbound=True,
        is_private_ip=False,
        is_new_destination=True,
        signals=["connected_unrecognized_host"],
    )

    d = event.to_dict()
    assert d["process_name"] == "curl.exe"
    assert d["remote_ip"] == "93.184.216.34"
    assert "connected_unrecognized_host" in d["signals"]
    assert d["event_id"] is not None

    json_str = event.to_json()
    parsed = json.loads(json_str)
    assert parsed["remote_port"] == 443
    assert parsed["is_new_destination"] is True


def test_is_private_or_local_ip():
    """Verify private/loopback RFC 1918 vs public external IP differentiation."""
    # Private / Local
    assert is_private_or_local_ip("127.0.0.1") is True
    assert is_private_or_local_ip("192.168.1.1") is True
    assert is_private_or_local_ip("10.0.0.1") is True
    assert is_private_or_local_ip("172.16.0.1") is True
    assert is_private_or_local_ip("::1") is True
    assert is_private_or_local_ip("169.254.1.1") is True

    # Public
    assert is_private_or_local_ip("8.8.8.8") is False
    assert is_private_or_local_ip("1.1.1.1") is False
    assert is_private_or_local_ip("142.250.190.46") is False


def test_unrecognized_destination_signal():
    """Verify first outbound connection to a public IP triggers connected_unrecognized_host."""
    monitor = NetworkMonitor()
    mock_conn = MockConn(
        fd=1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("192.168.1.100", 50000),
        raddr=MockAddr("93.184.216.34", 443),
        status="ESTABLISHED",
        pid=9000,
    )

    with patch.object(monitor, "get_process_info", return_value=("browser.exe", "C:\\browser.exe")):
        with patch("psutil.net_connections", return_value=[mock_conn]):
            events = monitor.scan_iteration()

    assert len(events) == 1
    assert "connected_unrecognized_host" in events[0].signals
    assert events[0].is_new_destination is True
    assert "93.184.216.34" in monitor.known_destinations

    # Second iteration to same host should NOT trigger connected_unrecognized_host again
    mock_conn2 = MockConn(
        fd=2,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("192.168.1.100", 50001),
        raddr=MockAddr("93.184.216.34", 443),
        status="ESTABLISHED",
        pid=9000,
    )
    with patch.object(monitor, "get_process_info", return_value=("browser.exe", "C:\\browser.exe")):
        with patch("psutil.net_connections", return_value=[mock_conn, mock_conn2]):
            events2 = monitor.scan_iteration()

    assert len(events2) == 1
    assert "connected_unrecognized_host" not in events2[0].signals


def test_suspicious_process_network_connection():
    """Verify powershell or cmd opening outbound connection raises signal."""
    monitor = NetworkMonitor()
    mock_conn = MockConn(
        fd=1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("192.168.1.100", 50002),
        raddr=MockAddr("104.244.42.1", 80),
        status="ESTABLISHED",
        pid=4500,
    )

    with patch.object(monitor, "get_process_info", return_value=("powershell.exe", "C:\\Windows\\System32\\powershell.exe")):
        with patch("psutil.net_connections", return_value=[mock_conn]):
            events = monitor.scan_iteration()

    assert len(events) == 1
    assert "suspicious_process_network_connection" in events[0].signals


def test_network_after_suspicious_process_activity():
    """Verify connection immediately following suspicious process activity raises signal."""
    monitor = NetworkMonitor()
    pid = 7777
    monitor.record_suspicious_process(pid)

    mock_conn = MockConn(
        fd=1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("192.168.1.100", 50003),
        raddr=MockAddr("185.199.108.153", 443),
        status="ESTABLISHED",
        pid=pid,
    )

    with patch.object(monitor, "get_process_info", return_value=("worker.exe", "C:\\worker.exe")):
        with patch("psutil.net_connections", return_value=[mock_conn]):
            events = monitor.scan_iteration()

    assert len(events) == 1
    assert "network_after_suspicious_process" in events[0].signals


def test_suspicious_destination_port():
    """Verify connection to typical reverse shell/C2 port raises signal."""
    config = NetworkMonitorConfig(suspicious_destination_ports=[4444, 1337])
    monitor = NetworkMonitor(config=config)

    mock_conn = MockConn(
        fd=1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("192.168.1.100", 50004),
        raddr=MockAddr("198.51.100.30", 4444),
        status="ESTABLISHED",
        pid=8888,
    )

    with patch.object(monitor, "get_process_info", return_value=("tool.exe", "C:\\tool.exe")):
        with patch("psutil.net_connections", return_value=[mock_conn]):
            events = monitor.scan_iteration()

    assert len(events) == 1
    assert "suspicious_destination_port" in events[0].signals

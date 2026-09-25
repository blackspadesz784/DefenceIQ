"""Bluetooth Communication Bridge for offline phone pairing.

Enables the Android Companion App to receive security status and high-risk alerts
over Bluetooth Low Energy (BLE) / RFCOMM without requiring local Wi-Fi or cables.
Defines DefenceIQ GATT service, characteristics, and robust framed chunking protocol.
"""

import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("defenceiq.comms.bluetooth_bridge")

# DefenceIQ standard GATT UUIDs
DEFENCEIQ_SERVICE_UUID = "19000001-def1-49ce-b84e-f4d3c0de0001"
DEFENCEIQ_STATUS_CHAR_UUID = "19000002-def1-49ce-b84e-f4d3c0de0001"
DEFENCEIQ_ALERT_CHAR_UUID = "19000003-def1-49ce-b84e-f4d3c0de0001"
DEFENCEIQ_COMMAND_CHAR_UUID = "19000004-def1-49ce-b84e-f4d3c0de0001"

# Frame type identifiers
FRAME_TYPE_STATUS = 0x01
FRAME_TYPE_ALERT = 0x02
FRAME_TYPE_COMMAND = 0x03
FRAME_TYPE_RESPONSE = 0x04


class PacketAssembler:
    """Reassembles chunked BLE frames into original UTF-8 / JSON messages."""

    def __init__(self):
        # Maps message_id -> {total, chunks: dict[seq, bytes]}
        self._buffers: Dict[int, Dict[str, Any]] = {}

    def feed_chunk(self, chunk: bytes) -> Optional[Dict[str, Any]]:
        """Consumes a framed byte chunk.

        Format: [msg_id: 1B][frame_type: 1B][seq: 1B][total: 1B][payload: NB]
        Returns the parsed JSON dict when the full message has assembled, else None.
        """
        if len(chunk) < 4:
            return None

        msg_id = chunk[0]
        frame_type = chunk[1]
        seq = chunk[2]
        total = chunk[3]
        payload = chunk[4:]

        if msg_id not in self._buffers:
            self._buffers[msg_id] = {
                "frame_type": frame_type,
                "total": total,
                "chunks": {},
            }

        buf = self._buffers[msg_id]
        buf["chunks"][seq] = payload

        if len(buf["chunks"]) == buf["total"]:
            # All chunks arrived, reassemble
            sorted_chunks = [buf["chunks"][i] for i in range(buf["total"])]
            complete_bytes = b"".join(sorted_chunks)
            del self._buffers[msg_id]
            try:
                text = complete_bytes.decode("utf-8")
                return json.loads(text)
            except Exception as e:
                logger.error(f"Error decoding reassembled frame {msg_id}: {e}")
                return None
        return None


def encode_frames(
    data: Dict[str, Any],
    frame_type: int = FRAME_TYPE_STATUS,
    msg_id: int = 1,
    mtu: int = 128,
) -> List[bytes]:
    """Encodes a dictionary into chunked frames fitting within the specified MTU.

    Frame format: [msg_id: 1B][frame_type: 1B][seq: 1B][total: 1B][payload: NB]
    Header overhead is 4 bytes.
    """
    raw_payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    payload_chunk_size = max(16, mtu - 4)

    chunks = []
    total = (len(raw_payload) + payload_chunk_size - 1) // payload_chunk_size
    if total == 0:
        total = 1

    for seq in range(total):
        start = seq * payload_chunk_size
        end = start + payload_chunk_size
        part = raw_payload[start:end]
        header = bytes([msg_id % 256, frame_type, seq, total])
        chunks.append(header + part)

    return chunks


class BluetoothBridge:
    """Manages Bluetooth Low Energy communications for DefenceIQ."""

    def __init__(self, device_name: str = "DefenceIQ-Agent"):
        self.device_name = device_name
        self.service_uuid = DEFENCEIQ_SERVICE_UUID
        self.status_char_uuid = DEFENCEIQ_STATUS_CHAR_UUID
        self.alert_char_uuid = DEFENCEIQ_ALERT_CHAR_UUID
        self.command_char_uuid = DEFENCEIQ_COMMAND_CHAR_UUID

        self._msg_counter = 0
        self._assembler = PacketAssembler()
        self._command_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
        self._is_advertising = False
        self._connected_clients: List[str] = []
        self._last_status: Optional[Dict[str, Any]] = None

    def register_command_handler(self, handler: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        """Registers a callback for executing incoming commands (e.g. rollback, ping)."""
        self._command_handler = handler

    def is_ble_supported(self) -> bool:
        """Checks if Bleak BLE library is available."""
        try:
            import bleak
            return True
        except ImportError:
            return False

    async def scan_for_companion_devices(self, timeout: float = 3.0) -> List[Dict[str, Any]]:
        """Scans for nearby BLE devices using BleakScanner if available."""
        if not self.is_ble_supported():
            logger.warning("Bleak library not available; cannot scan for BLE devices.")
            return []

        try:
            from bleak import BleakScanner
            devices = await BleakScanner.discover(timeout=timeout)
            results = []
            for dev in devices:
                name = dev.name or "Unknown"
                results.append({
                    "name": name,
                    "address": dev.address,
                    "rssi": getattr(dev, "rssi", 0),
                    "is_defenceiq": "defenceiq" in name.lower(),
                })
            return results
        except Exception as e:
            logger.error(f"Error during BLE discovery scan: {e}")
            return []

    def format_status_frames(self, status_data: Dict[str, Any], mtu: int = 128) -> List[bytes]:
        """Encodes current agent status into chunked BLE frames."""
        self._msg_counter = (self._msg_counter + 1) % 255
        self._last_status = status_data
        return encode_frames(status_data, frame_type=FRAME_TYPE_STATUS, msg_id=self._msg_counter, mtu=mtu)

    def format_alert_frames(self, incident_data: Dict[str, Any], mtu: int = 128) -> List[bytes]:
        """Encodes security incident alert into chunked BLE frames."""
        self._msg_counter = (self._msg_counter + 1) % 255
        return encode_frames(incident_data, frame_type=FRAME_TYPE_ALERT, msg_id=self._msg_counter, mtu=mtu)

    def receive_chunk(self, chunk: bytes) -> Optional[Dict[str, Any]]:
        """Processes an incoming raw BLE byte chunk."""
        parsed = self._assembler.feed_chunk(chunk)
        if parsed and self._command_handler:
            try:
                response = self._command_handler(parsed)
                return response
            except Exception as e:
                logger.error(f"Command handler error: {e}")
                return {"status": "error", "error": str(e)}
        return parsed

    def get_status(self) -> Dict[str, Any]:
        """Returns Bluetooth bridge status dictionary."""
        return {
            "ble_supported": self.is_ble_supported(),
            "device_name": self.device_name,
            "service_uuid": self.service_uuid,
            "status_char_uuid": self.status_char_uuid,
            "alert_char_uuid": self.alert_char_uuid,
            "command_char_uuid": self.command_char_uuid,
            "advertising": self._is_advertising,
            "connected_clients": list(self._connected_clients),
        }

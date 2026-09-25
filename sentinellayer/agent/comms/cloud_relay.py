"""DefenceIQ - Cloud Relay & Token-Based Messaging Channel.

Provides secure, IP-independent communication between laptop agent and mobile companion
using a unique pairing token. Neither device requires a static IP, port forwarding,
or being on the same Wi-Fi network.

Features:
- Token-based deterministic topic derivation (no IP exchange needed)
- End-to-end HMAC-SHA256 message integrity & authentication
- Real-time mobile push notifications for critical security events
- Bidirectional uplink (mobile -> laptop commands) and downlink (laptop -> mobile alerts)
- Automatic device identification & heartbeat telemetry
- Secure token rotation & revocation
- Privacy preservation: telemetry is strictly metadata-only (no file content transmission)
- Fully backwards compatible with existing test suite and legacy ntfy format
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
import platform
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("DefenceIQ.CloudRelay")


def derive_relay_channels(pairing_token: str) -> Dict[str, str]:
    """Derives deterministic relay topic names and authentication secrets from pairing token."""
    norm_token = pairing_token.strip().upper().replace("-", "")
    token_bytes = norm_token.encode("utf-8")

    # Hash derivations
    down_hash = hmac.new(token_bytes, b"DEFENCEIQ_DOWNLINK_V2", hashlib.sha256).hexdigest()
    up_hash = hmac.new(token_bytes, b"DEFENCEIQ_UPLINK_V2", hashlib.sha256).hexdigest()
    auth_secret = hmac.new(token_bytes, b"DEFENCEIQ_AUTH_KEY_V2", hashlib.sha256).hexdigest()

    return {
        "downlink_topic": f"diq_down_{down_hash[:20]}",
        "uplink_topic": f"diq_up_{up_hash[:20]}",
        "auth_secret": auth_secret,
        "normalized_token": norm_token,
    }


def sign_payload(payload_dict: Dict[str, Any], auth_secret: str) -> str:
    """Signs a JSON serializable dictionary using HMAC-SHA256."""
    canon_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(auth_secret.encode("utf-8"), canon_bytes, hashlib.sha256).hexdigest()


def verify_payload_signature(payload_dict: Dict[str, Any], signature: str, auth_secret: str) -> bool:
    """Verifies HMAC-SHA256 signature using constant-time comparison."""
    if not signature or not auth_secret:
        return False
    expected = sign_payload(payload_dict, auth_secret)
    return hmac.compare_digest(expected, signature)


@dataclass
class DeviceIdentification:
    """Laptop hardware and agent identity for mobile display."""
    device_id: str
    hostname: str
    os_name: str
    agent_version: str = "2.1.0"
    authorized_paths: List[str] = field(default_factory=list)
    protection_level: str = "balanced"
    paired_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def create_local(cls, authorized_paths: Optional[List[str]] = None, protection_level: str = "balanced") -> "DeviceIdentification":
        hostname = socket.gethostname()
        raw_id = f"{hostname}_{platform.machine()}_{os.name}"
        dev_id = f"LAPTOP-{hashlib.sha256(raw_id.encode('utf-8')).hexdigest()[:8].upper()}"
        paths = authorized_paths or [
            os.path.expandvars(r"%USERPROFILE%\Downloads"),
            os.path.expandvars(r"%USERPROFILE%\Desktop"),
            os.path.expandvars(r"%USERPROFILE%\Documents"),
        ]
        return cls(
            device_id=dev_id,
            hostname=hostname,
            os_name=f"{platform.system()} {platform.release()}",
            authorized_paths=paths,
            protection_level=protection_level,
        )


class CloudRelay:
    """Bidirectional token-based relay client for internet-wide mobile communications."""

    DEFAULT_NTFY_URL = "https://ntfy.sh"
    DEFAULT_RELAY_SERVER = DEFAULT_NTFY_URL

    def __init__(
        self,
        server_url: str = DEFAULT_NTFY_URL,
        topic: Optional[str] = None,
        pairing_token: Optional[str] = None,
        enabled: bool = True,
        on_command_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.enabled = enabled
        self.on_command_callback = on_command_callback
        self.pairing_token = pairing_token
        self.device_info = DeviceIdentification.create_local()

        self._listener_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._sent_alerts: List[Dict[str, Any]] = []
        self._seq = 0
        self._channels: Dict[str, str] = {}

        if topic:
            self.topic = topic
        elif pairing_token:
            digest = hashlib.sha256(pairing_token.encode("utf-8")).hexdigest()
            self.topic = f"defenceiq_{digest[:12]}"
        else:
            self.topic = "defenceiq_alerts_channel"

        if self.pairing_token:
            self.set_pairing_token(self.pairing_token)

    def set_enabled(self, enabled: bool) -> None:
        """Enables or disables cloud push notifications."""
        self.enabled = enabled
        logger.info(f"CloudRelay enabled set to {enabled}")

    def set_pairing_token(self, token: str) -> None:
        """Sets or updates the pairing token and re-derives secure topics and HMAC secret."""
        self.pairing_token = token.strip().upper()
        self._channels = derive_relay_channels(self.pairing_token)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.topic = f"defenceiq_{digest[:12]}"
        logger.info(
            f"Configured CloudRelay for pairing token [{self._channels['normalized_token'][:4]}****] "
            f"Downlink: {self._channels['downlink_topic']} | Uplink: {self._channels['uplink_topic']}"
        )

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns recorded alert history."""
        return list(self._sent_alerts)

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status dictionary for diagnostics and UI."""
        return {
            "enabled": self.enabled,
            "paired": bool(self.pairing_token),
            "server_url": self.server_url,
            "topic": self.topic,
            "device_id": self.device_info.device_id,
            "hostname": self.device_info.hostname,
            "downlink_topic": self._channels.get("downlink_topic", self.topic),
            "uplink_topic": self._channels.get("uplink_topic", "not_paired"),
            "total_alerts_sent": len(self._sent_alerts),
            "listener_active": self._listener_thread is not None and self._listener_thread.is_alive(),
            "authorized_paths": self.device_info.authorized_paths,
            "ip_independent": True,
        }

    # ========================================================================
    # Legacy Formatters & Publishers (for backwards compatibility)
    # ========================================================================

    def format_incident_payload(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Formats an incident event dictionary into a push notification payload."""
        score = incident.get("risk_score", 0)
        risk_band = incident.get("risk_band", "UNKNOWN").upper()
        incident_id = incident.get("incident_id", "N/A")
        process_name = incident.get("process_name") or incident.get("root_process_name", "Unknown process")
        action = incident.get("action_taken", "LOG")
        signals = incident.get("signals", [])

        if risk_band == "RED" or score >= 75:
            priority = "urgent"
            tags = ["rotating_light", "skull", "shield"]
            title = f"CRITICAL THREAT ({score}/100) - {process_name}"
        elif risk_band == "ORANGE" or score >= 50:
            priority = "high"
            tags = ["warning", "shield"]
            title = f"HIGH RISK ALERT ({score}/100) - {process_name}"
        else:
            priority = "default"
            tags = ["information_source", "shield"]
            title = f"Security Notice ({score}/100) - {process_name}"

        signal_summary = ", ".join(signals[:3]) if signals else "Suspicious behavior detected"
        message = (
            f"Action: {action}\n"
            f"Incident ID: {incident_id}\n"
            f"Signals: {signal_summary}\n"
            f"Risk Band: {risk_band}"
        )

        return {
            "title": title,
            "message": message,
            "priority": priority,
            "tags": tags,
            "incident_id": incident_id,
            "risk_score": score,
            "action": action,
        }

    def publish_alert(
        self,
        title: str,
        message: str,
        priority: str = "high",
        tags: Optional[List[str]] = None,
        click_url: Optional[str] = None,
        timeout: float = 4.0,
    ) -> bool:
        """Publishes a push notification to configured topic."""
        payload = {
            "topic": self.topic,
            "title": title,
            "message": message,
            "priority": priority,
            "tags": tags or ["shield"],
        }
        if click_url:
            payload["click"] = click_url

        self._sent_alerts.append(payload)

        if not self.enabled:
            logger.debug(f"CloudRelay is disabled; alert recorded locally but not pushed: {title}")
            return True

        endpoint = f"{self.server_url}/{self.topic}"
        safe_title = title.encode("ascii", "replace").decode("ascii")
        headers = {
            "Title": safe_title,
            "Priority": priority,
            "Tags": ",".join(tags or ["shield"]),
        }
        if click_url:
            headers["Click"] = click_url

        req = urllib.request.Request(
            endpoint,
            data=message.encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                if 200 <= status < 300:
                    logger.info(f"Cloud push alert sent to {self.topic}: {title}")
                    return True
                return False
        except Exception as e:
            logger.warning(f"Error publishing alert to cloud relay: {e}")
            return False

    def publish_incident(self, incident: Dict[str, Any]) -> bool:
        """Helper to format and publish an incident dict."""
        payload = self.format_incident_payload(incident)
        return self.publish_alert(
            title=payload["title"],
            message=payload["message"],
            priority=payload["priority"],
            tags=payload["tags"],
        )

    # ========================================================================
    # Enhanced Secure Token-Based Messaging (Downlink: Laptop -> Mobile)
    # ========================================================================

    def _send_envelope(self, msg_type: str, data: Dict[str, Any], priority: str = "default", push_title: Optional[str] = None) -> bool:
        """Constructs an HMAC-signed envelope and posts it to the downlink topic."""
        if not self.enabled or not self.pairing_token:
            logger.debug(f"CloudRelay not enabled or pairing token not set; message {msg_type} skipped.")
            return False

        topic = self._channels.get("downlink_topic", self.topic)
        auth_secret = self._channels.get("auth_secret", "fallback_secret")

        self._seq += 1
        envelope = {
            "v": 2,
            "type": msg_type,
            "seq": self._seq,
            "device_id": self.device_info.device_id,
            "hostname": self.device_info.hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        sig = sign_payload(envelope, auth_secret)
        envelope["hmac"] = sig

        body_str = json.dumps(envelope)
        endpoint = f"{self.server_url}/{topic}"

        headers = {
            "Content-Type": "application/json",
            "X-DefenceIQ-Type": msg_type,
            "Priority": priority,
        }
        if push_title:
            headers["Title"] = push_title.encode("ascii", "replace").decode("ascii")
            headers["Tags"] = "shield,warning" if priority in ("high", "urgent") else "shield"

        req = urllib.request.Request(
            endpoint,
            data=body_str.encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status = getattr(resp, "status", 200)
                if 200 <= status < 300:
                    logger.debug(f"Successfully published {msg_type} to {topic}")
                    return True
                return False
        except Exception as e:
            logger.warning(f"Error publishing {msg_type} to cloud relay: {e}")
            return False

    def publish_handshake(self) -> bool:
        """Sends device identification and authorization scopes to mobile app."""
        handshake_data = asdict(self.device_info)
        handshake_data["handshake_type"] = "LAPTOP_ANNOUNCE"
        handshake_data["privacy_guarantee"] = "Strict metadata telemetry only. No file contents transmitted."
        return self._send_envelope(
            msg_type="PAIR_HANDSHAKE",
            data=handshake_data,
            priority="high",
            push_title=f"DefenceIQ Linked: {self.device_info.hostname}",
        )

    def publish_threat_alert(self, incident: Dict[str, Any]) -> bool:
        """Sends real-time high priority push notification for threat incidents."""
        score = incident.get("risk_score", 0)
        risk_band = incident.get("risk_band", "UNKNOWN").upper()
        incident_id = incident.get("incident_id", "N/A")
        proc_name = incident.get("root_process_name") or incident.get("process_name", "Unknown process")
        signals = incident.get("signals", [])
        touched_files = incident.get("touched_files", [])
        explanation = incident.get("explanation", "")
        status = incident.get("status", "OPEN")

        if any("ransom" in s.lower() or "encrypt" in s.lower() for s in signals):
            threat_type = "Potential Ransomware Activity"
        elif any("script" in s.lower() or "powershell" in s.lower() for s in signals):
            threat_type = "Suspicious Script Execution"
        elif any("persist" in s.lower() or "autorun" in s.lower() for s in signals):
            threat_type = "Unauthorized Persistence / Autorun"
        elif any("c2" in s.lower() or "beacon" in s.lower() or "connect" in s.lower() for s in signals):
            threat_type = "Suspicious Outbound Network Connection"
        else:
            threat_type = f"Endpoint Anomaly ({proc_name})"

        if risk_band == "RED":
            recommended = "Process suspended and network contained. Verify process source."
            priority = "urgent"
            title = f"CRITICAL THREAT: {threat_type} ({score}/100)"
        elif risk_band == "ORANGE":
            recommended = "Elevated risk detected. Temporary network isolation recommended."
            priority = "high"
            title = f"HIGH RISK ALERT: {threat_type} ({score}/100)"
        else:
            recommended = "Review process signals and file modifications."
            priority = "default"
            title = f"Security Notice: {threat_type} ({score}/100)"

        safe_files = [os.path.basename(f) for f in touched_files[:5]]

        alert_data = {
            "title": title,
            "message": f"Threat: {threat_type} ({score}/100) - {recommended}",
            "incident_id": incident_id,
            "threat_type": threat_type,
            "severity": risk_band,
            "risk_score": score,
            "affected_process": proc_name,
            "affected_files": safe_files,
            "signals": signals,
            "timestamp": incident.get("updated_at") or datetime.now(timezone.utc).isoformat(),
            "recommended_action": recommended,
            "explanation": explanation,
            "status": status,
            "rollback_available": status in ("CONTAINED", "OPEN"),
        }

        self._sent_alerts.append(alert_data)
        return self._send_envelope(
            msg_type="THREAT_ALERT",
            data=alert_data,
            priority=priority,
            push_title=title,
        )

    def publish_status_heartbeat(self, status_dict: Dict[str, Any]) -> bool:
        """Publishes periodic endpoint status and telemetry overview."""
        sanitized = {
            "health_state": status_dict.get("health_state", "SECURE"),
            "protection_level": status_dict.get("protection_level", self.device_info.protection_level),
            "monitored_pids_count": status_dict.get("monitored_pids_count", 0),
            "active_sockets_count": status_dict.get("active_sockets_count", 0),
            "stats": status_dict.get("stats", {}),
            "authorized_paths": self.device_info.authorized_paths,
            "device_id": self.device_info.device_id,
            "hostname": self.device_info.hostname,
        }
        return self._send_envelope(
            msg_type="STATUS_UPDATE",
            data=sanitized,
            priority="low",
        )

    def publish_revocation(self) -> bool:
        """Notifies mobile app that pairing has been revoked by laptop user."""
        res = self._send_envelope(
            msg_type="REVOKE_PAIRING",
            data={"reason": "Pairing revoked from laptop security settings"},
            priority="high",
            push_title="DefenceIQ Pairing Revoked",
        )
        self.stop()
        self.pairing_token = None
        self._channels = {}
        return res

    # ========================================================================
    # Listening Methods (Uplink: Mobile -> Laptop Commands)
    # ========================================================================

    def start_listener(self) -> None:
        """Starts background polling/streaming listener for incoming mobile commands."""
        if not self.pairing_token or not self.enabled:
            return
        if self._listener_thread and self._listener_thread.is_alive():
            return

        self._stop_event.clear()
        self._listener_thread = threading.Thread(
            target=self._uplink_listener_loop,
            daemon=True,
            name="DefenceIQ-RelayUplinkListener",
        )
        self._listener_thread.start()
        logger.info("Started CloudRelay uplink listener thread.")

    def _uplink_listener_loop(self) -> None:
        """Polls uplink topic for authenticated mobile commands using long-polling."""
        topic = self._channels.get("uplink_topic")
        auth_secret = self._channels.get("auth_secret")
        if not topic or not auth_secret:
            return

        endpoint = f"{self.server_url}/{topic}/json?poll=1"
        logger.info(f"Relay listener active on uplink topic: {topic}")

        while not self._stop_event.is_set():
            try:
                req = urllib.request.Request(endpoint, headers={"User-Agent": "DefenceIQ-Agent"})
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    lines = resp.read().decode("utf-8").strip().splitlines()
                    for line in lines:
                        if not line.strip():
                            continue
                        try:
                            msg_frame = json.loads(line)
                            raw_msg = msg_frame.get("message")
                            if not raw_msg:
                                continue
                            envelope = json.loads(raw_msg)
                            sig = envelope.pop("hmac", None)
                            if sig and verify_payload_signature(envelope, sig, auth_secret):
                                self._dispatch_incoming_command(envelope)
                            else:
                                logger.warning("Received uplink message with invalid HMAC signature; dropping.")
                        except Exception as e:
                            logger.debug(f"Failed parsing message line: {e}")
            except urllib.error.URLError:
                pass
            except Exception as e:
                logger.debug(f"Uplink loop exception: {e}")

            time.sleep(2.0)

    def _dispatch_incoming_command(self, envelope: Dict[str, Any]) -> None:
        """Executes authorized commands sent from the paired mobile device."""
        cmd_type = envelope.get("type")
        data = envelope.get("data", {})
        logger.info(f"Received verified mobile command: {cmd_type} -> {data}")

        if cmd_type == "REVOKE_PAIRING":
            logger.warning("Mobile requested device unpairing. Revoking pairing token.")
            self.stop()
            self.pairing_token = None
            self._channels = {}
            return

        if self.on_command_callback:
            try:
                self.on_command_callback(envelope)
            except Exception as e:
                logger.error(f"Error in command callback: {e}")

    def stop(self) -> None:
        """Stops background listener threads."""
        self._stop_event.set()
        self._listener_thread = None
        logger.info("CloudRelay stopped.")

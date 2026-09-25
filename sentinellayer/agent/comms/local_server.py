"""DefenceIQ - Local LAN Communications & Alerts Server.

Provides a fast, local-first REST and WebSocket API for the Android companion
app and dashboard over the local Wi-Fi network. Supports pairing token
authentication, real-time alert broadcasts, containment rollbacks, and
protection status control.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import secrets
import socket
import threading
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Security, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
import uvicorn

from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.config.settings import ProtectionLevel, Settings, default_settings
from sentinellayer.agent.response.response_engine import ResponseActionRecord, ResponseEngine
from sentinellayer.agent.storage.db import LocalDatabase

logger = logging.getLogger("DefenceIQ.LocalServer")


def get_local_lan_ip() -> str:
    """Detects the primary LAN IP address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually transmit data; determines routing interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class ProtectionLevelUpdateRequest(BaseModel):
    level: str = Field(..., description="Protection level: basic, balanced, or maximum")


class PairRequest(BaseModel):
    token: str = Field(..., description="Laptop pairing token entered on mobile device")


class MobilePairRequest(BaseModel):
    token: str = Field(..., description="Unique mobile generated pairing token (e.g. DIQ-XXXX-XXXX)")


class ConnectionManager:
    """Tracks active WebSocket subscribers and broadcasts real-time alert frames."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WebSocket client paired and connected. Active count: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Active count: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Dispatches JSON message payload to all active WebSocket clients."""
        async with self._lock:
            sockets = list(self.active_connections)

        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.debug(f"Error sending message to WebSocket client: {e}")
                async with self._lock:
                    self.active_connections.discard(ws)


class LocalServer:
    """FastAPI & WebSocket server for local companion app communications."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8765,
        settings: Optional[Settings] = None,
        db: Optional[LocalDatabase] = None,
        response_engine: Optional[ResponseEngine] = None,
        pairing_token: Optional[str] = None,
        usb_bridge: Optional[Any] = None,
        bluetooth_bridge: Optional[Any] = None,
        cloud_relay: Optional[Any] = None,
    ):
        self.host = host
        self.port = port
        self.settings = settings or default_settings
        self.db = db or LocalDatabase(db_path=self.settings.db_path)
        self.response_engine = response_engine or ResponseEngine(settings=self.settings)

        # Monitored processes and network stats handles (optional runtime references)
        self.process_monitor: Optional[Any] = None
        self.network_monitor: Optional[Any] = None

        # Transport bridges
        self.usb_bridge = usb_bridge
        self.bluetooth_bridge = bluetooth_bridge
        self.cloud_relay = cloud_relay

        # Pairing token setup
        self.pairing_token_file = self.settings.pairing_token_file
        self.pairing_token = pairing_token or self._load_or_create_token()

        self.ws_manager = ConnectionManager()
        self.server: Optional[uvicorn.Server] = None
        self._server_task: Optional[asyncio.Task] = None
        self._thread: Optional[threading.Thread] = None

        self.app = FastAPI(
            title="DefenceIQ Local API",
            description="Local Wi-Fi communication and telemetry endpoint for DefenceIQ Companion App",
            version="1.0.0",
        )
        self._setup_middleware()
        self._setup_routes()

    def _load_or_create_token(self) -> str:
        """Loads pairing token from disk or generates a fresh cryptographically secure code."""
        if os.path.isfile(self.pairing_token_file):
            try:
                with open(self.pairing_token_file, "r", encoding="utf-8") as f:
                    token = f.read().strip()
                if token:
                    return token
            except Exception as e:
                logger.warning(f"Could not read pairing token file: {e}")

        # Generate a fresh 8-character uppercase hex token (e.g., 'C4A8D9F1')
        token = secrets.token_hex(4).upper()
        try:
            with open(self.pairing_token_file, "w", encoding="utf-8") as f:
                f.write(token + "\n")
        except Exception as e:
            logger.warning(f"Could not write pairing token to file: {e}")
        return token

    def verify_token(self, token: Optional[str]) -> bool:
        """Validates client pairing token using constant-time comparison."""
        if not token:
            return False
        return secrets.compare_digest(token.strip().upper(), self.pairing_token.strip().upper())

    def _setup_middleware(self):
        """Configures CORS allowing local phone connections."""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def _setup_routes(self):
        """Registers all REST and WebSocket routes on the FastAPI instance."""
        bearer_scheme = HTTPBearer(auto_error=False)

        def authenticate(
            auth_header: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
            x_pairing_token: Optional[str] = Header(None, alias="X-Pairing-Token"),
            token: Optional[str] = Query(None),
        ):
            # Check Bearer token first, then custom header, then query parameter
            candidate = None
            if auth_header and auth_header.credentials:
                candidate = auth_header.credentials
            elif x_pairing_token:
                candidate = x_pairing_token
            elif token:
                candidate = token

            if not self.verify_token(candidate):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing pairing token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return candidate

        # --- Health, Dashboard & Pairing ---

        @self.app.get("/", response_class=HTMLResponse)
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard():
            """Serves the standalone Cyber-Dark Web Companion Dashboard for mobile browsers."""
            from sentinellayer.agent.comms.dashboard import get_dashboard_html
            return HTMLResponse(content=get_dashboard_html(), status_code=200)

        @self.app.get("/health")
        async def health():
            """Unauthenticated health ping."""
            return {"status": "ok", "service": "DefenceIQ Agent"}

        @self.app.post("/pair")
        async def pair(payload: PairRequest):
            """Tests or performs initial pairing from mobile app."""
            if not self.verify_token(payload.token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid pairing token",
                )
            return {
                "success": True,
                "message": "Successfully paired with DefenceIQ Laptop Security Agent",
                "lan_ip": get_local_lan_ip(),
                "hostname": socket.gethostname(),
                "protection_level": self.settings.protection_level.value,
            }

        @self.app.post("/pair-mobile")
        async def pair_mobile(payload: MobilePairRequest):
            """Pairs laptop with mobile app using a unique pairing token without IP dependency."""
            norm_token = payload.token.strip().upper()
            if len(norm_token) < 4:
                raise HTTPException(status_code=400, detail="Pairing token must be at least 4 characters")

            self.pairing_token = norm_token
            try:
                with open(self.pairing_token_file, "w", encoding="utf-8") as f:
                    f.write(norm_token + "\n")
            except Exception as e:
                logger.warning(f"Could not persist pairing token to disk: {e}")

            dev_id = socket.gethostname()
            if self.cloud_relay:
                self.cloud_relay.set_pairing_token(norm_token)
                self.cloud_relay.enabled = True
                self.cloud_relay.publish_handshake()
                self.cloud_relay.start_listener()
                dev_id = self.cloud_relay.device_info.device_id

            await self.ws_manager.broadcast({
                "type": "paired_mobile",
                "token": norm_token,
                "device_id": dev_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            return {
                "success": True,
                "message": f"Successfully paired with Mobile Device using token {norm_token}",
                "token": norm_token,
                "device_id": dev_id,
                "hostname": socket.gethostname(),
                "cloud_relay": self.cloud_relay.get_status() if self.cloud_relay else None,
            }

        @self.app.post("/revoke-pairing")
        async def revoke_pairing():
            """Revokes pairing token, unlinks mobile device, and rotates security secrets."""
            if self.cloud_relay:
                self.cloud_relay.publish_revocation()

            if os.path.isfile(self.pairing_token_file):
                try:
                    os.remove(self.pairing_token_file)
                except Exception:
                    pass

            self.pairing_token = secrets.token_hex(4).upper()

            await self.ws_manager.broadcast({
                "type": "pairing_revoked",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            return {
                "success": True,
                "message": "Pairing successfully revoked and secrets rotated.",
                "new_token": self.pairing_token,
            }

        @self.app.get("/monitoring-scope")
        async def get_monitoring_scope():
            """Returns authorized file and process scopes and user privacy assurances."""
            paths = [os.path.expandvars(p) for p in self.settings.file_monitor.watch_paths]
            return {
                "authorized_directories": paths,
                "executable_extensions": self.settings.file_monitor.executable_extensions,
                "suspicious_process_names": self.settings.process_monitor.suspicious_process_names,
                "privacy_guarantee": "Least privilege: Telemetry sends only metadata (process name, sha256 hash, entropy score, risk signals). No sensitive file contents are ever read or transmitted.",
                "containment_policy": "Reversible containment: process suspension and temporary firewall rules only.",
            }

        # --- System Status ---

        @self.app.get("/status")
        async def get_status(_=Depends(authenticate)):
            """Consolidated agent telemetry, detection engine states, and metrics."""
            stats = self.db.get_system_stats()

            monitored_pids = 0
            if self.process_monitor and hasattr(self.process_monitor, "known_processes"):
                monitored_pids = len(self.process_monitor.known_processes)

            active_sockets = 0
            if self.network_monitor and hasattr(self.network_monitor, "active_sockets"):
                active_sockets = len(self.network_monitor.active_sockets)

            # Determine aggregate health status
            if stats["incidents_by_band"]["RED"] > 0:
                health_state = "CRITICAL_THREAT"
            elif stats["incidents_by_band"]["ORANGE"] > 0:
                health_state = "ELEVATED_RISK"
            elif stats["incidents_by_band"]["YELLOW"] > 0:
                health_state = "WARNING"
            else:
                health_state = "SECURE"

            return {
                "health_state": health_state,
                "protection_level": self.settings.protection_level.value,
                "hostname": socket.gethostname(),
                "lan_ip": get_local_lan_ip(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "monitored_pids_count": monitored_pids,
                "active_sockets_count": active_sockets,
                "stats": stats,
                "engines": {
                    "static_analysis": "ready",
                    "yara_engine": "ready",
                    "reputation_engine": "ready",
                    "signature_engine": "ready",
                    "correlator": "active",
                    "response_engine": "active",
                },
            }

        # --- Incidents & Explainability ---

        @self.app.get("/incidents")
        async def list_incidents(
            limit: int = Query(50, ge=1, le=200),
            min_band: Optional[str] = Query(None),
            _=Depends(authenticate),
        ):
            """Retrieves recent incidents with full explainability scores and signals."""
            incidents = self.db.get_recent_incidents(limit=limit, min_band=min_band)
            return {"count": len(incidents), "incidents": incidents}

        @self.app.get("/incidents/{incident_id}")
        async def get_incident(incident_id: str, _=Depends(authenticate)):
            """Retrieves single incident details and audit trail of containment actions."""
            inc = self.db.get_incident(incident_id)
            if not inc:
                raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
            actions = self.db.get_incident_actions(incident_id)
            inc["actions"] = actions
            return inc

        @self.app.post("/incidents/{incident_id}/rollback")
        async def rollback_incident(incident_id: str, _=Depends(authenticate)):
            """Executes automated, reversible rollback for all actions taken on an incident."""
            inc = self.db.get_incident(incident_id)
            if not inc:
                raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

            results = self.response_engine.rollback_incident(incident_id)
            self.db.update_incident_status(incident_id, "ROLLED_BACK")

            # Broadcast update via WebSocket
            await self.ws_manager.broadcast({
                "type": "incident_rollback",
                "incident_id": incident_id,
                "results": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            return {
                "success": True,
                "incident_id": incident_id,
                "status": "ROLLED_BACK",
                "results": results,
            }

        @self.app.post("/incidents/{incident_id}/resolve")
        async def resolve_incident(incident_id: str, _=Depends(authenticate)):
            """Manually marks an incident as resolved without triggering containment rollback."""
            ok = self.db.resolve_incident(incident_id)
            if not ok:
                raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

            await self.ws_manager.broadcast({
                "type": "incident_resolved",
                "incident_id": incident_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return {"success": True, "incident_id": incident_id, "status": "RESOLVED"}

        # --- Protection Controls ---

        @self.app.post("/protection/level")
        async def set_protection_level(payload: ProtectionLevelUpdateRequest, _=Depends(authenticate)):
            """Updates agent protection mode (Basic, Balanced, Maximum)."""
            level_str = payload.level.lower()
            try:
                new_level = ProtectionLevel(level_str)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid level '{level_str}'. Must be one of: basic, balanced, maximum",
                )

            self.settings.protection_level = new_level
            self.response_engine.settings.protection_level = new_level
            logger.info(f"Agent Protection Level updated to: {new_level.value.upper()}")

            await self.ws_manager.broadcast({
                "type": "protection_level_changed",
                "level": new_level.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            return {"success": True, "protection_level": new_level.value}

        # --- Quarantine Vault Management ---

        @self.app.get("/quarantine")
        async def list_quarantined_files(
            include_restored: bool = Query(False),
            _=Depends(authenticate),
        ):
            """Lists all files in the safe quarantine vault with restoration metadata."""
            files = self.response_engine.quarantine.list_quarantined(include_restored=include_restored)
            return {"count": len(files), "quarantined_files": files}

        @self.app.post("/quarantine/{quarantine_id}/restore")
        async def restore_quarantined_file(quarantine_id: str, _=Depends(authenticate)):
            """Restores a quarantined file back to its original location."""
            ok = self.response_engine.quarantine.restore_file(quarantine_id)
            if not ok:
                raise HTTPException(
                    status_code=400,
                    detail=f"Could not restore quarantined file with ID {quarantine_id}",
                )

            await self.ws_manager.broadcast({
                "type": "quarantine_restored",
                "quarantine_id": quarantine_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return {"success": True, "quarantine_id": quarantine_id, "status": "RESTORED"}

        # --- Transport Status ---

        @self.app.get("/transports")
        async def get_transports_status(_=Depends(authenticate)):
            """Returns status of LAN, USB ADB bridge, Bluetooth, and Cloud Relay transports."""
            return {
                "lan": {
                    "ip": get_local_lan_ip(),
                    "port": self.port,
                    "connected_clients": len(self.ws_manager.active_connections),
                },
                "usb": self.usb_bridge.get_status() if self.usb_bridge else {"available": False},
                "bluetooth": self.bluetooth_bridge.get_status() if self.bluetooth_bridge else {"available": False},
                "cloud": self.cloud_relay.get_status() if self.cloud_relay else {"available": False},
            }

        # --- WebSocket Alerts Feed ---

        @self.app.websocket("/ws/alerts")
        async def websocket_alerts(
            websocket: WebSocket,
            token: Optional[str] = Query(None),
        ):
            """Real-time bidirectional WebSocket stream for events, scores, and alerts."""
            # Check token parameter or Authorization header
            client_token = token
            if not client_token:
                auth_header = websocket.headers.get("authorization", "")
                if auth_header.lower().startswith("bearer "):
                    client_token = auth_header[7:].strip()
                elif "x-pairing-token" in websocket.headers:
                    client_token = websocket.headers["x-pairing-token"]

            if not self.verify_token(client_token):
                logger.warning("Rejected unauthenticated WebSocket connection attempt")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            await self.ws_manager.connect(websocket)

            # Send initial connection handshake snapshot
            await websocket.send_json({
                "type": "connected",
                "message": "Connected to DefenceIQ Live Security Stream",
                "lan_ip": get_local_lan_ip(),
                "hostname": socket.gethostname(),
                "protection_level": self.settings.protection_level.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            try:
                while True:
                    data = await websocket.receive_text()
                    try:
                        parsed = json.loads(data)
                        msg_type = parsed.get("type")
                        if msg_type == "ping":
                            await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
                    except Exception:
                        pass
            except WebSocketDisconnect:
                await self.ws_manager.disconnect(websocket)
            except Exception as e:
                logger.debug(f"WebSocket client loop ended: {e}")
                await self.ws_manager.disconnect(websocket)

    # ========================================================================
    # Broadcasting Helper Methods
    # ========================================================================

    async def broadcast_incident(self, incident: Incident):
        """Asynchronously dispatches an incident update to connected mobile clients."""
        score_val = incident.score_result.score if incident.score_result else 0
        band_val = incident.score_result.band if incident.score_result else "GREEN"
        explanation = incident.score_result.explanation if incident.score_result else ""
        contrib = [
            {"name": s.name, "weight": s.weight, "category": s.category, "description": s.description}
            for s in (incident.score_result.contributing_signals if incident.score_result else [])
        ]

        payload = {
            "type": "incident",
            "incident": {
                "incident_id": incident.incident_id,
                "created_at": datetime.fromtimestamp(incident.created_at, timezone.utc).isoformat(),
                "updated_at": datetime.fromtimestamp(incident.updated_at, timezone.utc).isoformat(),
                "root_pid": incident.root_pid,
                "root_process_name": incident.root_process_name,
                "involved_pids": list(incident.involved_pids),
                "touched_files": list(incident.touched_files),
                "network_destinations": list(incident.network_destinations),
                "signals": list(incident.signals),
                "risk_score": score_val,
                "risk_band": band_val,
                "contributing_signals": contrib,
                "explanation": explanation,
                "status": incident.status,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.ws_manager.broadcast(payload)

        # Dispatch real-time threat alert to cloud relay for mobile push notification
        if self.cloud_relay and self.cloud_relay.enabled and (band_val in ("YELLOW", "ORANGE", "RED") or score_val >= 20):
            try:
                self.cloud_relay.publish_threat_alert(payload["incident"])
                self.cloud_relay.publish_incident(payload["incident"])
            except Exception as e:
                logger.debug(f"Cloud relay push error: {e}")

        # Update bluetooth bridge if present
        if self.bluetooth_bridge:
            try:
                self.bluetooth_bridge.format_alert_frames(payload["incident"])
            except Exception as e:
                logger.debug(f"Bluetooth bridge frame error: {e}")

    async def broadcast_action(self, action: ResponseActionRecord):
        """Asynchronously dispatches a containment action event to connected clients."""
        payload = {
            "type": "action",
            "action": action.to_dict(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.ws_manager.broadcast(payload)

    async def broadcast_event(self, domain: str, event_type: str, summary: str, signals: List[str]):
        """Dispatches a brief telemetry event summary."""
        payload = {
            "type": "telemetry_event",
            "domain": domain,
            "event_type": event_type,
            "summary": summary,
            "signals": signals,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.ws_manager.broadcast(payload)

    # ========================================================================
    # Server Lifecycle Management
    # ========================================================================

    async def start(self):
        """Asynchronously starts the Uvicorn server in the current event loop."""
        config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config=config)
        self.print_banner()
        await self.server.serve()

    def start_in_thread(self) -> threading.Thread:
        """Runs the server in a separate background thread with its own asyncio loop."""
        def _run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            config = uvicorn.Config(
                app=self.app,
                host=self.host,
                port=self.port,
                log_level="warning",
                access_log=False,
            )
            self.server = uvicorn.Server(config=config)
            self.print_banner()
            loop.run_until_complete(self.server.serve())

        self._thread = threading.Thread(target=_run, daemon=True, name="DefenceIQ-LocalServer")
        self._thread.start()
        return self._thread

    def stop(self):
        """Gracefully signals the Uvicorn server to stop."""
        if self.server:
            self.server.should_exit = True
            logger.info("LocalServer stop requested")

    def print_banner(self):
        """Displays friendly terminal banner with connection IP and pairing token."""
        lan_ip = get_local_lan_ip()
        print("\n" + "=" * 65)
        print("  DEFENCEIQ - LOCAL WI-FI API & COMPANION SERVER")
        print("=" * 65)
        print(f"  Local IP Address   : http://{lan_ip}:{self.port}")
        print(f"  Localhost Endpoint : http://127.0.0.1:{self.port}")
        print(f"  WebSocket Stream   : ws://{lan_ip}:{self.port}/ws/alerts")
        print("=" * 65)
        print(f"  >>> PAIRING TOKEN  : {self.pairing_token} <<<")
        print("  (Enter this token in the DefenceIQ Android companion app)")
        print("=" * 65 + "\n")

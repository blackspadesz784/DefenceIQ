"""DefenceIQ - SQLite Database Storage Layer.

Manages persistent SQLite storage for telemetry events, explainable incidents,
and containment action audit trails.
"""

from datetime import datetime, timezone
import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.monitors.process_monitor import ProcessEvent
from sentinellayer.agent.monitors.file_monitor import FileEvent
from sentinellayer.agent.monitors.network_monitor import NetworkEvent
from sentinellayer.agent.monitors.usb_monitor import USBEvent
from sentinellayer.agent.response.response_engine import ResponseActionRecord
from sentinellayer.agent.storage.models import (
    StoredActionRecord,
    StoredEventRecord,
    StoredIncidentRecord,
)

logger = logging.getLogger("DefenceIQ.Database")


class LocalDatabase:
    """Thread-safe SQLite storage engine for DefenceIQ."""

    def __init__(self, db_path: str = "defenceiq.db"):
        self.db_path = os.path.abspath(db_path)
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._lock = threading.Lock()
        self.init_db()

    @contextmanager
    def _get_connection(self):
        """Yields a connection configured with WAL mode and reliably closes it on exit."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            conn.close()

    def init_db(self):
        """Initializes tables and indexes if they do not already exist."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # 1. Telemetry Events Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        domain TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        pid INTEGER,
                        details_json TEXT,
                        signals_json TEXT
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);")

                # 2. Correlated Incidents Table (with Explainability)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        root_pid INTEGER NOT NULL,
                        root_process_name TEXT NOT NULL,
                        involved_pids TEXT,
                        touched_files TEXT,
                        network_destinations TEXT,
                        signals TEXT,
                        risk_score INTEGER NOT NULL,
                        risk_band TEXT NOT NULL,
                        contributing_signals TEXT,
                        explanation TEXT NOT NULL,
                        actions_taken TEXT,
                        status TEXT NOT NULL DEFAULT 'OPEN'
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_band ON incidents(risk_band);")

                # 3. Containment Actions Audit Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS actions (
                        action_id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        executed_at TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        rollback_handler TEXT,
                        details_json TEXT
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_actions_incident ON actions(incident_id);")

                conn.commit()
                logger.info(f"Initialized SQLite database at: {self.db_path}")

    # ========================================================================
    # Telemetry Event Operations
    # ========================================================================
    def save_event(self, event: Any) -> Optional[str]:
        """Persists a ProcessEvent, FileEvent, or NetworkEvent to SQLite."""
        if isinstance(event, ProcessEvent):
            domain = "PROCESS"
            pid = event.pid
        elif isinstance(event, FileEvent):
            domain = "FILE"
            pid = event.metadata.get("pid")
        elif isinstance(event, NetworkEvent):
            domain = "NETWORK"
            pid = event.pid
        elif isinstance(event, USBEvent):
            domain = "USB"
            pid = None
        else:
            return None

        event_id = getattr(event, "event_id", "")
        event_type = getattr(event, "event_type", "")
        timestamp = getattr(event, "timestamp", datetime.now(timezone.utc).isoformat())
        signals = getattr(event, "signals", [])
        details = event.to_dict() if hasattr(event, "to_dict") else {}

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO events (event_id, domain, event_type, timestamp, pid, details_json, signals_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        domain,
                        event_type,
                        timestamp,
                        pid,
                        json.dumps(details),
                        json.dumps(signals),
                    ),
                )
                conn.commit()
        return event_id

    # ========================================================================
    # Incident & Explainability Operations
    # ========================================================================
    def save_incident(self, incident: Incident) -> str:
        """Persists or updates an Incident record with full explainability metadata."""
        score_res = incident.score_result
        score = score_res.score if score_res else 0
        band = score_res.band if score_res else "GREEN"
        explanation = score_res.explanation if score_res else ""
        contrib = [
            {
                "name": s.name,
                "weight": s.weight,
                "category": s.category,
                "description": s.description,
            }
            for s in (score_res.contributing_signals if score_res else [])
        ]

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO incidents (
                        incident_id, created_at, updated_at, root_pid, root_process_name,
                        involved_pids, touched_files, network_destinations, signals,
                        risk_score, risk_band, contributing_signals, explanation, actions_taken, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        datetime.fromtimestamp(incident.created_at, timezone.utc).isoformat(),
                        datetime.fromtimestamp(incident.updated_at, timezone.utc).isoformat(),
                        incident.root_pid,
                        incident.root_process_name,
                        json.dumps(list(incident.involved_pids)),
                        json.dumps(list(incident.touched_files)),
                        json.dumps(list(incident.network_destinations)),
                        json.dumps(list(incident.signals)),
                        score,
                        band,
                        json.dumps(contrib),
                        explanation,
                        json.dumps([]),
                        incident.status,
                    ),
                )
                conn.commit()
        return incident.incident_id

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident by ID with parsed JSON structures."""
        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
                if not row:
                    return None

                rec = StoredIncidentRecord(
                    incident_id=row["incident_id"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    root_pid=row["root_pid"],
                    root_process_name=row["root_process_name"],
                    involved_pids_json=row["involved_pids"],
                    touched_files_json=row["touched_files"],
                    network_destinations_json=row["network_destinations"],
                    signals_json=row["signals"],
                    risk_score=row["risk_score"],
                    risk_band=row["risk_band"],
                    contributing_signals_json=row["contributing_signals"],
                    explanation=row["explanation"],
                    actions_taken_json=row["actions_taken"],
                    status=row["status"],
                )
                return rec.to_dict()

    def get_recent_incidents(
        self, limit: int = 50, min_band: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves recently updated incidents, optionally filtered by minimum band."""
        band_hierarchy = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}
        min_level = band_hierarchy.get((min_band or "GREEN").upper(), 0)

        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()

                results = []
                for row in rows:
                    band = row["risk_band"]
                    if band_hierarchy.get(band, 0) >= min_level:
                        rec = StoredIncidentRecord(
                            incident_id=row["incident_id"],
                            created_at=row["created_at"],
                            updated_at=row["updated_at"],
                            root_pid=row["root_pid"],
                            root_process_name=row["root_process_name"],
                            involved_pids_json=row["involved_pids"],
                            touched_files_json=row["touched_files"],
                            network_destinations_json=row["network_destinations"],
                            signals_json=row["signals"],
                            risk_score=row["risk_score"],
                            risk_band=row["risk_band"],
                            contributing_signals_json=row["contributing_signals"],
                            explanation=row["explanation"],
                            actions_taken_json=row["actions_taken"],
                            status=row["status"],
                        )
                        results.append(rec.to_dict())
                return results

    def update_incident_status(self, incident_id: str, status: str) -> bool:
        """Updates the status (OPEN, CONTAINED, ROLLED_BACK, RESOLVED) of an incident."""
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                    (status, datetime.now(timezone.utc).isoformat(), incident_id),
                )
                conn.commit()
                return cur.rowcount > 0

    def resolve_incident(self, incident_id: str) -> bool:
        """Marks an incident as resolved."""
        return self.update_incident_status(incident_id, "RESOLVED")

    # ========================================================================
    # Containment Action Operations
    # ========================================================================
    def save_action(self, action: ResponseActionRecord) -> str:
        """Saves a containment action audit record."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO actions (
                        action_id, incident_id, action_type, target, executed_at,
                        success, rollback_handler, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action.action_id,
                        action.incident_id,
                        action.action_type,
                        action.target,
                        action.executed_at,
                        1 if action.success else 0,
                        action.rollback_handler,
                        json.dumps(action.details),
                    ),
                )
                conn.commit()
        return action.action_id

    def get_incident_actions(self, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieves all containment actions executed for an incident."""
        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM actions WHERE incident_id = ? ORDER BY executed_at ASC",
                    (incident_id,),
                ).fetchall()

                results = []
                for row in rows:
                    rec = StoredActionRecord(
                        action_id=row["action_id"],
                        incident_id=row["incident_id"],
                        action_type=row["action_type"],
                        target=row["target"],
                        executed_at=row["executed_at"],
                        success=bool(row["success"]),
                        rollback_handler=row["rollback_handler"],
                        details_json=row["details_json"],
                    )
                    results.append(rec.to_dict())
                return results

    def get_system_stats(self) -> Dict[str, Any]:
        """Returns consolidated database statistics for dashboard monitoring."""
        with self._lock:
            with self._get_connection() as conn:
                total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                red_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE risk_band = 'RED'").fetchone()[0]
                orange_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE risk_band = 'ORANGE'").fetchone()[0]
                yellow_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE risk_band = 'YELLOW'").fetchone()[0]
                total_actions = conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0]

                return {
                    "total_events": total_events,
                    "total_incidents": total_incidents,
                    "incidents_by_band": {
                        "RED": red_incidents,
                        "ORANGE": orange_incidents,
                        "YELLOW": yellow_incidents,
                        "GREEN": total_incidents - (red_incidents + orange_incidents + yellow_incidents),
                    },
                    "total_actions": total_actions,
                }

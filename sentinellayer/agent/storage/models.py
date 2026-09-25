"""DefenceIQ - Database Models and Storage Data Structures.

Provides data representations for stored telemetry events, explainable incidents,
and containment action audit records.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class StoredEventRecord:
    """Represents a persisted telemetry event."""
    event_id: str
    domain: str  # PROCESS, FILE, NETWORK
    event_type: str
    timestamp: str
    pid: Optional[int]
    details_json: str
    signals_json: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "domain": self.domain,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "details": json.loads(self.details_json) if self.details_json else {},
            "signals": json.loads(self.signals_json) if self.signals_json else [],
        }


@dataclass
class StoredIncidentRecord:
    """Represents an explainable security incident persisted in SQLite."""
    incident_id: str
    created_at: str
    updated_at: str
    root_pid: int
    root_process_name: str
    involved_pids_json: str
    touched_files_json: str
    network_destinations_json: str
    signals_json: str
    risk_score: int
    risk_band: str
    contributing_signals_json: str
    explanation: str
    actions_taken_json: str
    status: str = "OPEN"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "root_pid": self.root_pid,
            "root_process_name": self.root_process_name,
            "involved_pids": json.loads(self.involved_pids_json) if self.involved_pids_json else [],
            "touched_files": json.loads(self.touched_files_json) if self.touched_files_json else [],
            "network_destinations": json.loads(self.network_destinations_json) if self.network_destinations_json else [],
            "signals": json.loads(self.signals_json) if self.signals_json else [],
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "contributing_signals": json.loads(self.contributing_signals_json) if self.contributing_signals_json else [],
            "explanation": self.explanation,
            "actions_taken": json.loads(self.actions_taken_json) if self.actions_taken_json else [],
            "status": self.status,
        }


@dataclass
class StoredActionRecord:
    """Represents an audit log entry for a containment action."""
    action_id: str
    incident_id: str
    action_type: str
    target: str
    executed_at: str
    success: bool
    rollback_handler: str
    details_json: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "target": self.target,
            "executed_at": self.executed_at,
            "success": self.success,
            "rollback_handler": self.rollback_handler,
            "details": json.loads(self.details_json) if self.details_json else {},
        }

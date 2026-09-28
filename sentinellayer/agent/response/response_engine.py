"""DefenceIQ - Graduated Response Engine.

Orchestrates containment actions tied to risk score bands and configured
protection levels (Basic, Balanced, Maximum). All actions are reversible
and logged with automated rollback execution paths.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional

from sentinellayer.agent.ai_engine.event_correlator import Incident
from sentinellayer.agent.config.settings import ProtectionLevel, Settings, default_settings
from sentinellayer.agent.response.firewall_controller import FirewallController
from sentinellayer.agent.response.process_controller import ProcessController
from sentinellayer.agent.response.quarantine import QuarantineManager

logger = logging.getLogger("DefenceIQ.ResponseEngine")


@dataclass
class ResponseActionRecord:
    """Record of a containment action executed for an incident."""
    action_id: str
    incident_id: str
    action_type: str  # LOG, NOTIFY, SUSPEND, BLOCK_NETWORK, QUARANTINE, ISOLATE
    target: str  # PID or file path or rule name
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    success: bool = True
    rollback_handler: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponseEngine:
    """Evaluates incidents and applies graduated, reversible containment actions."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        firewall_controller: Optional[FirewallController] = None,
        process_controller: Optional[ProcessController] = None,
        quarantine_manager: Optional[QuarantineManager] = None,
    ):
        self.settings = settings or default_settings
        self.firewall = firewall_controller or FirewallController()
        self.processes = process_controller or ProcessController()
        self.quarantine = quarantine_manager or QuarantineManager()

        # Audit log of all actions taken: incident_id -> List[ResponseActionRecord]
        self.incident_actions: Dict[str, List[ResponseActionRecord]] = {}

    def handle_incident(self, incident: Incident) -> List[ResponseActionRecord]:
        """Evaluates incident risk band and executes graduated containment actions."""
        if not incident.score_result:
            return []

        band = incident.score_result.band
        level = self.settings.protection_level
        actions_taken: List[ResponseActionRecord] = []

        # Determine graduated actions based on protection level and risk band
        if band == "GREEN":
            # Green: Log only
            actions_taken.append(
                ResponseActionRecord(
                    action_id=f"act_{len(actions_taken)}",
                    incident_id=incident.incident_id,
                    action_type="LOG",
                    target=str(incident.root_pid),
                    details={"message": "Logged within baseline parameters"},
                )
            )

        elif band == "YELLOW":
            # Yellow: Notify + increased monitoring
            actions_taken.append(
                ResponseActionRecord(
                    action_id=f"act_{len(actions_taken)}",
                    incident_id=incident.incident_id,
                    action_type="NOTIFY",
                    target=str(incident.root_pid),
                    details={"score": incident.score_result.score, "signals": incident.signals},
                )
            )
            if level == ProtectionLevel.MAXIMUM:
                # In Maximum protection, block network on Yellow
                self._apply_network_block(incident, actions_taken)

        elif band == "ORANGE":
            # Orange: Block network + suspend process
            actions_taken.append(
                ResponseActionRecord(
                    action_id=f"act_{len(actions_taken)}",
                    incident_id=incident.incident_id,
                    action_type="NOTIFY",
                    target=str(incident.root_pid),
                    details={"score": incident.score_result.score},
                )
            )
            if level != ProtectionLevel.BASIC:
                self._apply_network_block(incident, actions_taken)
                self._apply_process_suspension(incident, actions_taken)

        elif band == "RED":
            # Red: Suspend + Isolate process, quarantine files, block network
            self._apply_network_block(incident, actions_taken)
            self._apply_process_suspension(incident, actions_taken)
            self._apply_process_isolation(incident, actions_taken)

            if level != ProtectionLevel.BASIC:
                self._apply_quarantine(incident, actions_taken)

        # Store actions in history
        if actions_taken:
            self.incident_actions.setdefault(incident.incident_id, []).extend(actions_taken)
            incident.status = "CONTAINED" if band in ("ORANGE", "RED") else "OPEN"

        return actions_taken

    def _apply_network_block(self, incident: Incident, actions: List[ResponseActionRecord]):
        """Blocks network access for involved process executables."""
        import psutil

        blocked_exes = set()
        for pid in incident.involved_pids:
            try:
                proc = psutil.Process(pid)
                exe = proc.exe()
                if exe and exe not in blocked_exes:
                    blocked_exes.add(exe)
                    res = self.firewall.block_process(exe)
                    actions.append(
                        ResponseActionRecord(
                            action_id=f"fw_{pid}",
                            incident_id=incident.incident_id,
                            action_type="BLOCK_NETWORK",
                            target=exe,
                            success=res.get("success", False),
                            rollback_handler=f"unblock_process('{res.get('rule_name')}')",
                            details=res,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _apply_process_suspension(self, incident: Incident, actions: List[ResponseActionRecord]):
        """Reversibly suspends all involved processes."""
        current_pid = os.getpid()
        for pid in incident.involved_pids:
            if pid == current_pid:
                continue
            res = self.processes.suspend_process(pid)
            actions.append(
                ResponseActionRecord(
                    action_id=f"proc_susp_{pid}",
                    incident_id=incident.incident_id,
                    action_type="SUSPEND",
                    target=str(pid),
                    success=res.get("success", False),
                    rollback_handler=f"resume_process({pid})",
                    details=res,
                )
            )

    def _apply_process_isolation(self, incident: Incident, actions: List[ResponseActionRecord]):
        """Isolates process tree by suspending remaining child processes."""
        if incident.root_pid == os.getpid():
            return
        res = self.processes.isolate_process(incident.root_pid)
        actions.append(
            ResponseActionRecord(
                action_id=f"proc_iso_{incident.root_pid}",
                incident_id=incident.incident_id,
                action_type="ISOLATE",
                target=str(incident.root_pid),
                success=res.get("success", False),
                rollback_handler=f"resume_all()",
                details=res,
            )
        )

    def _apply_quarantine(self, incident: Incident, actions: List[ResponseActionRecord]):
        """Safely quarantines touched or dropped files associated with the incident."""
        for file_path in incident.touched_files:
            res = self.quarantine.quarantine_file(
                file_path=file_path,
                reason=f"Incident {incident.incident_id[:8]} Red band containment",
                signals=incident.signals,
                incident_id=incident.incident_id,
            )
            actions.append(
                ResponseActionRecord(
                    action_id=f"quar_{res.get('quarantine_id', 'unknown')[:8]}",
                    incident_id=incident.incident_id,
                    action_type="QUARANTINE",
                    target=file_path,
                    success=res.get("success", False),
                    rollback_handler=res.get("rollback_action", ""),
                    details=res,
                )
            )

    def rollback_incident(self, incident_id: str) -> Dict[str, Any]:
        """Reverses all containment actions taken for a specific incident."""
        actions = self.incident_actions.get(incident_id, [])
        results = {"unblocked_rules": [], "resumed_pids": [], "restored_files": []}

        for act in actions:
            # 1. Rollback Firewall
            if act.action_type == "BLOCK_NETWORK":
                rule_name = act.details.get("rule_name")
                if rule_name:
                    if self.firewall.unblock_process(rule_name):
                        results["unblocked_rules"].append(rule_name)

            # 2. Rollback Process Suspension
            elif act.action_type in ("SUSPEND", "ISOLATE"):
                try:
                    pid = int(act.target)
                    if self.processes.resume_process(pid):
                        results["resumed_pids"].append(pid)
                except ValueError:
                    pass

            # 3. Rollback Quarantine
            elif act.action_type == "QUARANTINE":
                qid = act.details.get("quarantine_id")
                if qid:
                    if self.quarantine.restore_file(qid):
                        results["restored_files"].append(act.target)

        logger.info(f"Incident {incident_id[:8]} containment successfully rolled back: {results}")
        return results

    def rollback_all(self) -> Dict[str, Any]:
        """Rollback: System-wide undo of all containment actions."""
        return {
            "firewall": self.firewall.rollback_all(),
            "processes": self.processes.resume_all(),
        }

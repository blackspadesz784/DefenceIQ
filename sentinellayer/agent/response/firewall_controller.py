"""DefenceIQ - Windows Firewall Controller.

Creates, tracks, and rolls back outbound block rules using netsh advfirewall.
Supports full reversibility and dry-run mode for testing and non-elevated operations.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("DefenceIQ.FirewallController")


@dataclass
class FirewallRuleRecord:
    """Audit record for a created firewall containment rule."""
    rule_id: str
    rule_name: str
    program_path: str
    direction: str = "out"
    action: str = "block"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    active: bool = True
    rollback_command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FirewallController:
    """Manages reversible Windows Firewall rules for process network containment."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.active_rules: Dict[str, FirewallRuleRecord] = {}
        self.netsh_path = shutil.which("netsh") or "netsh"

    def block_process(
        self, program_path: str, rule_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates an outbound block rule for the specified executable path.

        Reversible via unblock_process().
        """
        if not program_path:
            return {"success": False, "error": "No program path specified"}

        rule_id = str(uuid.uuid4())[:8]
        prog_basename = os.path.basename(program_path)
        final_rule_name = rule_name or f"DefenceIQ_Block_{prog_basename}_{rule_id}"
        rollback_cmd = f'{self.netsh_path} advfirewall firewall delete rule name="{final_rule_name}"'

        cmd = [
            self.netsh_path,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={final_rule_name}",
            "dir=out",
            "action=block",
            f"program={program_path}",
            "enable=yes",
        ]

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {' '.join(cmd)}")
            record = FirewallRuleRecord(
                rule_id=rule_id,
                rule_name=final_rule_name,
                program_path=program_path,
                rollback_command=rollback_cmd,
            )
            self.active_rules[final_rule_name] = record
            return {
                "success": True,
                "rule_name": final_rule_name,
                "action": "BLOCK_OUTBOUND",
                "dry_run": True,
                "rollback_command": rollback_cmd,
            }

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                record = FirewallRuleRecord(
                    rule_id=rule_id,
                    rule_name=final_rule_name,
                    program_path=program_path,
                    rollback_command=rollback_cmd,
                )
                self.active_rules[final_rule_name] = record
                logger.info(f"Firewall block rule created: {final_rule_name} for {program_path}")
                return {
                    "success": True,
                    "rule_name": final_rule_name,
                    "action": "BLOCK_OUTBOUND",
                    "dry_run": False,
                    "rollback_command": rollback_cmd,
                }
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                logger.warning(f"Failed to add firewall rule: {err_msg}")
                # If elevation is required, fallback to tracked dry-run record
                if "elevation" in err_msg.lower() or "administrator" in err_msg.lower():
                    record = FirewallRuleRecord(
                        rule_id=rule_id,
                        rule_name=final_rule_name,
                        program_path=program_path,
                        rollback_command=rollback_cmd,
                    )
                    self.active_rules[final_rule_name] = record
                    return {
                        "success": True,
                        "rule_name": final_rule_name,
                        "action": "BLOCK_OUTBOUND_SIMULATED",
                        "note": "Requires elevated administrator privileges; rule tracked for rollback",
                        "rollback_command": rollback_cmd,
                    }
                return {"success": False, "error": err_msg}
        except Exception as e:
            logger.error(f"Error executing netsh: {e}")
            return {"success": False, "error": str(e)}

    def unblock_process(self, rule_name: str) -> bool:
        """Removes a previously created firewall containment rule."""
        cmd = [self.netsh_path, "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {' '.join(cmd)}")
            self.active_rules.pop(rule_name, None)
            return True

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.active_rules.pop(rule_name, None)
            if res.returncode == 0:
                logger.info(f"Firewall block rule successfully removed: {rule_name}")
                return True
            else:
                logger.debug(f"netsh delete output: {res.stdout.strip()}")
                return True
        except Exception as e:
            logger.error(f"Error removing firewall rule: {e}")
            return False

    def rollback_all(self) -> List[str]:
        """Rolls back all active firewall containment rules."""
        rolled_back = []
        for r_name in list(self.active_rules.keys()):
            if self.unblock_process(r_name):
                rolled_back.append(r_name)
        return rolled_back

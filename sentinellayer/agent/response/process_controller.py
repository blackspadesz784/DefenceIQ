"""DefenceIQ - Process Controller.

Performs reversible process suspension and process tree containment via psutil.
Maintains a full rollback registry to resume suspended processes.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional
import psutil

logger = logging.getLogger("DefenceIQ.ProcessController")


@dataclass
class SuspendedProcessRecord:
    """Audit record for a suspended process."""
    pid: int
    name: str
    exe: Optional[str]
    suspended_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProcessController:
    """Manages reversible suspension, resumption, and isolation of processes."""

    def __init__(self):
        self.suspended_processes: Dict[int, SuspendedProcessRecord] = {}

    def suspend_process(self, pid: int) -> Dict[str, Any]:
        """Reversibly suspends a target process using psutil NtSuspendProcess.

        Can be undone via resume_process().
        """
        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None

            p.suspend()
            record = SuspendedProcessRecord(pid=pid, name=name, exe=exe)
            self.suspended_processes[pid] = record
            logger.info(f"Process suspended: {name} (PID {pid})")

            return {
                "success": True,
                "action": "SUSPEND",
                "pid": pid,
                "name": name,
                "exe": exe,
                "rollback_action": f"resume_process({pid})",
            }
        except psutil.NoSuchProcess:
            return {"success": False, "error": "NoSuchProcess", "pid": pid}
        except psutil.AccessDenied:
            logger.warning(f"Access denied trying to suspend PID {pid}. May require elevation.")
            return {"success": False, "error": "AccessDenied", "pid": pid}
        except Exception as e:
            logger.error(f"Failed to suspend PID {pid}: {e}")
            return {"success": False, "error": str(e), "pid": pid}

    def resume_process(self, pid: int) -> bool:
        """Resumes a previously suspended process."""
        try:
            p = psutil.Process(pid)
            p.resume()
            self.suspended_processes.pop(pid, None)
            logger.info(f"Process resumed: PID {pid}")
            return True
        except psutil.NoSuchProcess:
            self.suspended_processes.pop(pid, None)
            return True
        except Exception as e:
            logger.error(f"Failed to resume PID {pid}: {e}")
            return False

    def isolate_process(self, pid: int) -> Dict[str, Any]:
        """Suspends the target process and all of its spawned child processes."""
        results = []
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            # Suspend children first, then parent
            for child in children:
                results.append(self.suspend_process(child.pid))
            results.append(self.suspend_process(pid))
            return {"success": True, "action": "ISOLATE_TREE", "details": results}
        except psutil.NoSuchProcess:
            return {"success": False, "error": "NoSuchProcess", "pid": pid}
        except Exception as e:
            return {"success": False, "error": str(e), "pid": pid}

    def resume_all(self) -> List[int]:
        """Rollback: Resumes all currently suspended processes."""
        resumed = []
        for pid in list(self.suspended_processes.keys()):
            if self.resume_process(pid):
                resumed.append(pid)
        return resumed

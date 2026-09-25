"""DefenceIQ - ClamAV Signature Engine Wrapper.

Wraps ClamAV scanning via pyclamd daemon socket or the clamscan/clamdscan
CLI binaries. Gracefully handles environments where ClamAV is not installed.
"""

import logging
import os
import shutil
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger("DefenceIQ.SignatureEngine")

try:
    import pyclamd
    HAS_PYCLAMD = True
except ImportError:
    pyclamd = None
    HAS_PYCLAMD = False


class SignatureEngine:
    """ClamAV signature engine supporting both daemon (pyclamd) and CLI (clamscan) execution."""

    def __init__(
        self,
        clamd_host: str = "127.0.0.1",
        clamd_port: int = 3310,
        clamscan_path: Optional[str] = None,
    ):
        self.clamd_host = clamd_host
        self.clamd_port = clamd_port
        self.clamscan_path = clamscan_path or shutil.which("clamdscan") or shutil.which("clamscan")
        self.cd = None

        self._init_client()

    def _init_client(self):
        """Initializes connection to ClamAV daemon if available."""
        if HAS_PYCLAMD:
            try:
                self.cd = pyclamd.ClamdNetworkSocket(self.clamd_host, self.clamd_port)
                if self.cd.ping():
                    logger.info("Connected to ClamAV daemon via pyclamd socket.")
                    return
            except Exception as e:
                logger.debug(f"Could not connect to pyclamd daemon socket: {e}")
                self.cd = None

        if self.clamscan_path:
            logger.info(f"ClamAV CLI binary detected: {self.clamscan_path}")
        else:
            logger.info("ClamAV daemon and CLI are not currently installed or available.")

    def is_available(self) -> bool:
        """Returns True if ClamAV daemon or CLI is accessible."""
        if self.cd:
            try:
                return self.cd.ping()
            except Exception:
                return False
        return bool(self.clamscan_path and os.path.isfile(self.clamscan_path))

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scans a file using ClamAV daemon or CLI.

        Returns detection details and signals.
        """
        if not os.path.isfile(file_path):
            return {"status": "FILE_NOT_FOUND", "is_infected": False, "virus_name": None, "signals": []}

        # 1. Daemon Scan via pyclamd
        if self.cd:
            try:
                result = self.cd.scan_file(os.path.abspath(file_path))
                # Result format: {filepath: ('FOUND', 'VirusName')} or None
                if result:
                    status, virus_name = list(result.values())[0]
                    return {
                        "status": "INFECTED",
                        "is_infected": True,
                        "virus_name": virus_name,
                        "engine": "pyclamd",
                        "signals": ["clamav_malware_detected"],
                    }
                return {
                    "status": "CLEAN",
                    "is_infected": False,
                    "virus_name": None,
                    "engine": "pyclamd",
                    "signals": [],
                }
            except Exception as e:
                logger.debug(f"pyclamd scan exception: {e}")

        # 2. CLI Scan via clamscan / clamdscan
        if self.clamscan_path:
            try:
                cmd = [self.clamscan_path, "--no-summary", file_path]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                # clamscan returns 0 for clean, 1 for virus found
                if proc.returncode == 1:
                    output = proc.stdout.strip()
                    # Output format: "C:\path\to\file: VirusName FOUND"
                    virus_name = "Threat.Detected"
                    if "FOUND" in output:
                        parts = output.split(":")
                        if len(parts) > 1:
                            virus_name = parts[1].replace("FOUND", "").strip()
                    return {
                        "status": "INFECTED",
                        "is_infected": True,
                        "virus_name": virus_name,
                        "engine": "clamscan_cli",
                        "signals": ["clamav_malware_detected"],
                    }
                elif proc.returncode == 0:
                    return {
                        "status": "CLEAN",
                        "is_infected": False,
                        "virus_name": None,
                        "engine": "clamscan_cli",
                        "signals": [],
                    }
            except Exception as e:
                logger.debug(f"ClamAV CLI execution error: {e}")

        # 3. ClamAV Not Available on Host
        return {
            "status": "CLAMAV_NOT_AVAILABLE",
            "is_infected": False,
            "virus_name": None,
            "engine": "none",
            "signals": [],
            "note": "ClamAV not installed on this host; layered detection continues via YARA and static analysis",
        }

"""USB Cable Bridge using Android Debug Bridge (ADB) for direct offline pairing.

Allows the Android Companion App to communicate with the DefenceIQ agent
over a direct USB cable connection without needing to be on the same Wi-Fi network.
Configures port forwarding (adb forward tcp:8765 tcp:8765) so the phone accesses
the agent at http://127.0.0.1:8765 and ws://127.0.0.1:8765/ws/alerts.
"""

import asyncio
import logging
import os
import shutil
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger("defenceiq.comms.usb_bridge")


class USBBridge:
    """Manages ADB port forwarding and USB-attached Android devices."""

    COMMON_ADB_PATHS = [
        r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe",
        r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
        r"C:\Program Files\Android\platform-tools\adb.exe",
    ]

    def __init__(self, adb_path: Optional[str] = None, local_port: int = 8765, remote_port: int = 8765):
        self.local_port = local_port
        self.remote_port = remote_port
        self.adb_path = adb_path or self._find_adb()
        self._is_monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._active_forwards: List[str] = []

    def _find_adb(self) -> Optional[str]:
        """Locates the adb executable on PATH or in common Android SDK locations."""
        which_adb = shutil.which("adb")
        if which_adb:
            return which_adb

        for candidate in self.COMMON_ADB_PATHS:
            expanded = os.path.expandvars(candidate)
            if os.path.isfile(expanded):
                return expanded
        return None

    def is_available(self) -> bool:
        """Returns True if adb binary is available and executable."""
        if not self.adb_path:
            self.adb_path = self._find_adb()
        if not self.adb_path:
            return False

        try:
            res = subprocess.run(
                [self.adb_path, "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            return res.returncode == 0
        except Exception as e:
            logger.debug(f"ADB check failed: {e}")
            return False

    def list_devices(self) -> List[Dict[str, str]]:
        """Lists connected Android devices via 'adb devices -l'.

        Returns list of dicts with:
            - serial: device serial number
            - state: 'device', 'unauthorized', 'offline', etc.
            - model: device model if reported
            - usb: usb port if reported
        """
        if not self.is_available():
            return []

        try:
            res = subprocess.run(
                [self.adb_path, "devices", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                logger.warning(f"adb devices failed: {res.stderr.strip()}")
                return []

            devices = []
            lines = res.stdout.strip().splitlines()
            for line in lines[1:]:  # Skip "List of devices attached"
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    serial = parts[0]
                    state = parts[1]
                    info = {"serial": serial, "state": state, "model": "Unknown", "usb": ""}
                    for part in parts[2:]:
                        if part.startswith("model:"):
                            info["model"] = part.split("model:", 1)[1]
                        elif part.startswith("usb:"):
                            info["usb"] = part.split("usb:", 1)[1]
                    devices.append(info)
            return devices
        except Exception as e:
            logger.error(f"Error listing adb devices: {e}")
            return []

    def setup_forward(self, serial: Optional[str] = None) -> bool:
        """Sets up port forwarding: adb forward tcp:<remote_port> tcp:<local_port>."""
        if not self.is_available():
            logger.warning("ADB not available; cannot setup USB port forward.")
            return False

        cmd = [self.adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(["forward", f"tcp:{self.remote_port}", f"tcp:{self.local_port}"])

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                forward_entry = f"tcp:{self.remote_port} -> tcp:{self.local_port}"
                if serial:
                    forward_entry = f"[{serial}] {forward_entry}"
                if forward_entry not in self._active_forwards:
                    self._active_forwards.append(forward_entry)
                logger.info(f"ADB port forward active: {forward_entry}")
                return True
            else:
                logger.warning(f"ADB forward failed: {res.stderr.strip()}")
                return False
        except Exception as e:
            logger.error(f"Exception executing adb forward: {e}")
            return False

    def remove_forward(self, serial: Optional[str] = None) -> bool:
        """Removes the port forward rule."""
        if not self.is_available():
            return False

        cmd = [self.adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(["forward", "--remove", f"tcp:{self.remote_port}"])

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            self._active_forwards = [
                f for f in self._active_forwards if f"tcp:{self.remote_port}" not in f
            ]
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Exception removing adb forward: {e}")
            return False

    def list_active_forwards(self) -> List[str]:
        """Queries adb for all active port forwards via 'adb forward --list'."""
        if not self.is_available():
            return []

        try:
            res = subprocess.run(
                [self.adb_path, "forward", "--list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
                return lines
            return []
        except Exception as e:
            logger.error(f"Exception querying adb forward list: {e}")
            return []

    async def start_auto_forward(self, poll_interval: float = 3.0) -> None:
        """Continuously monitors for connected devices and establishes forward rules."""
        self._is_monitoring = True
        logger.info("Starting USBBridge auto-forward monitor loop.")
        while self._is_monitoring:
            try:
                devices = self.list_devices()
                authorized = [d for d in devices if d["state"] == "device"]
                for dev in authorized:
                    self.setup_forward(dev["serial"])
            except Exception as e:
                logger.debug(f"USBBridge monitor loop tick error: {e}")
            await asyncio.sleep(poll_interval)

    def stop_auto_forward(self) -> None:
        """Stops the background auto-forward monitor loop."""
        self._is_monitoring = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
        logger.info("Stopped USBBridge auto-forward monitor loop.")

    def get_status(self) -> Dict:
        """Returns bridge status dictionary for dashboard / API."""
        return {
            "adb_available": self.is_available(),
            "adb_path": self.adb_path,
            "local_port": self.local_port,
            "remote_port": self.remote_port,
            "devices": self.list_devices() if self.is_available() else [],
            "active_forwards": self.list_active_forwards() if self.is_available() else [],
            "monitoring": self._is_monitoring,
        }

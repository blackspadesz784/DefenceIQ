"""DefenceIQ - Network Monitoring Service.

Tracks outbound connections per process using psutil, flags connections to
unrecognized/newly-seen destinations, and detects network activity immediately
following suspicious process activity. Emits structured events.
"""

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import socket
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

import psutil

from sentinellayer.agent.config.settings import NetworkMonitorConfig, default_settings

logger = logging.getLogger("DefenceIQ.NetworkMonitor")


def is_private_or_local_ip(ip_str: str) -> bool:
    """Returns True if the IP address is local, private (RFC 1918), loopback, or non-global."""
    if not ip_str:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_global
    except ValueError:
        return False


# ============================================================================
# Structured Network Event Schema
# ============================================================================
@dataclass
class NetworkEvent:
    """Structured telemetry event emitted for network connection activity."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = "CONNECTION_ESTABLISHED"  # CONNECTION_ESTABLISHED, CONNECTION_CLOSED
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_exe: Optional[str] = None
    protocol: str = "TCP"
    local_address: str = ""
    remote_address: str = ""
    remote_ip: str = ""
    remote_port: int = 0
    status: str = "ESTABLISHED"
    is_outbound: bool = True
    is_private_ip: bool = False
    is_new_destination: bool = False
    signals: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to standard dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize event to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Network Monitor
# ============================================================================
class NetworkMonitor:
    """Continuously monitors outbound network connections per process.

    Detects new destinations, connections from scripting shells, and
    outbound connections following suspicious process creation.
    """

    def __init__(
        self,
        event_bus: Optional[asyncio.Queue] = None,
        config: Optional[NetworkMonitorConfig] = None,
    ):
        self.event_bus = event_bus
        self.config = config or default_settings.network_monitor
        self.callbacks: List[Callable[[NetworkEvent], None]] = []
        self._running = False

        # Active tracked connections: key -> (pid, laddr, raddr, protocol)
        self._active_connections: Set[Tuple[Optional[int], str, str, str]] = set()

        # History of recognized destinations: set of remote_ip strings
        self.known_destinations: Set[str] = set()

        # Suspicious processes tracking: pid -> timestamp of suspicious event
        self._recent_suspicious_pids: Dict[int, float] = {}
        self.suspicious_process_window_seconds: float = 30.0

        # Fast lookup sets
        self._suspicious_process_names = {
            name.lower() for name in self.config.suspicious_process_names
        }
        self._suspicious_ports = set(self.config.suspicious_destination_ports)

    def register_callback(self, callback: Callable[[NetworkEvent], None]):
        """Register a callback handler for emitted network events."""
        self.callbacks.append(callback)

    def record_suspicious_process(self, pid: int):
        """Notifies the network monitor that a suspicious process event was detected for this PID."""
        self._recent_suspicious_pids[pid] = time.time()

    def prune_suspicious_processes(self):
        """Cleans up expired suspicious PID entries."""
        now = time.time()
        cutoff = now - self.suspicious_process_window_seconds
        expired = [pid for pid, ts in self._recent_suspicious_pids.items() if ts < cutoff]
        for pid in expired:
            self._recent_suspicious_pids.pop(pid, None)

    def emit_event(self, event: NetworkEvent):
        """Dispatches event to the event queue and registered callbacks."""
        if self.event_bus is not None:
            try:
                self.event_bus.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Event queue full; dropped network event %s", event.event_id)

        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in NetworkMonitor callback: {e}")

    def get_process_info(self, pid: Optional[int]) -> Tuple[Optional[str], Optional[str]]:
        """Safely looks up the process name and exe path for a PID."""
        if not pid:
            return None, None
        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None
            return name, exe
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None, None

    def initialize_baseline(self):
        """Populates known connections and initial external destinations."""
        self._active_connections.clear()
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.raddr:
                    r_ip, r_port = c.raddr.ip, c.raddr.port
                    l_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    r_str = f"{r_ip}:{r_port}"
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    conn_key = (c.pid, l_str, r_str, proto)
                    self._active_connections.add(conn_key)

                    if not is_private_or_local_ip(r_ip):
                        self.known_destinations.add(r_ip)
            logger.info(
                f"Network baseline initialized with {len(self._active_connections)} active connections and {len(self.known_destinations)} known destinations."
            )
        except Exception as e:
            logger.warning(f"Unable to read initial network baseline: {e}")

    def scan_iteration(self) -> List[NetworkEvent]:
        """Performs a single network connection scan iteration."""
        events: List[NetworkEvent] = []
        current_keys: Set[Tuple[Optional[int], str, str, str]] = set()

        self.prune_suspicious_processes()

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.debug(f"Error reading net_connections: {e}")
            return events

        for c in raw_conns:
            # We only evaluate active or initiating connections that have a remote target
            if not c.raddr:
                continue

            r_ip = c.raddr.ip
            r_port = c.raddr.port
            l_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            r_str = f"{r_ip}:{r_port}"
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            conn_key = (c.pid, l_str, r_str, proto)
            current_keys.add(conn_key)

            if conn_key not in self._active_connections:
                # NEW OUTBOUND CONNECTION
                self._active_connections.add(conn_key)

                proc_name, proc_exe = self.get_process_info(c.pid)
                proc_name_lower = (proc_name or "").lower()

                is_private = is_private_or_local_ip(r_ip)
                is_new_dest = False
                signals: List[str] = []

                # 1. Unrecognized / newly-seen public host
                if not is_private:
                    if r_ip not in self.known_destinations:
                        is_new_dest = True
                        self.known_destinations.add(r_ip)
                        signals.append("connected_unrecognized_host")

                # 2. Suspicious process opening outbound connection
                if proc_name_lower in self._suspicious_process_names:
                    signals.append("suspicious_process_network_connection")

                # 3. Connection immediately following suspicious process activity
                if c.pid and c.pid in self._recent_suspicious_pids:
                    signals.append("network_after_suspicious_process")

                # 4. Known suspicious ports
                if r_port in self._suspicious_ports:
                    signals.append("suspicious_destination_port")

                event = NetworkEvent(
                    event_type="CONNECTION_ESTABLISHED",
                    pid=c.pid,
                    process_name=proc_name,
                    process_exe=proc_exe,
                    protocol=proto,
                    local_address=l_str,
                    remote_address=r_str,
                    remote_ip=r_ip,
                    remote_port=r_port,
                    status=c.status,
                    is_outbound=True,
                    is_private_ip=is_private,
                    is_new_destination=is_new_dest,
                    signals=signals,
                    metadata={"family": str(c.family)},
                )

                events.append(event)
                self.emit_event(event)

        # Detect closed connections
        closed_keys = self._active_connections - current_keys
        for key in closed_keys:
            self._active_connections.discard(key)
            c_pid, l_str, r_str, proto = key
            r_ip = r_str.split(":")[0] if ":" in r_str else r_str
            proc_name, _ = self.get_process_info(c_pid)

            term_event = NetworkEvent(
                event_type="CONNECTION_CLOSED",
                pid=c_pid,
                process_name=proc_name,
                protocol=proto,
                local_address=l_str,
                remote_address=r_str,
                remote_ip=r_ip,
                status="CLOSED",
                is_outbound=True,
                is_private_ip=is_private_or_local_ip(r_ip),
                signals=[],
            )
            events.append(term_event)
            self.emit_event(term_event)

        return events

    async def start(self):
        """Runs the network monitoring loop asynchronously."""
        self._running = True
        self.initialize_baseline()
        logger.info(
            f"Network monitor started. Poll interval: {self.config.poll_interval_seconds}s"
        )

        while self._running:
            try:
                self.scan_iteration()
            except Exception as e:
                logger.error(f"Error during network monitor scan iteration: {e}", exc_info=True)

            await asyncio.sleep(self.config.poll_interval_seconds)

    def stop(self):
        """Stops the network monitor loop."""
        self._running = False
        logger.info("Network monitor stopped.")

    async def run_demo(self, duration_seconds: int = 15):
        """Runs a live console demonstration of network connection tracking."""
        print("=" * 70)
        print("  DEFENCEIQ - NETWORK MONITORING DEMO (Phase 3)")
        print("=" * 70)
        print(f"Monitoring active network connections for {duration_seconds} seconds...")
        print("TIP: Browse a website or ping an external server to see new destinations live!")
        print("=" * 70)

        def print_event(ev: NetworkEvent):
            print("\n[+] NETWORK EVENT DETECTED:")
            print(ev.to_json(indent=2))

        self.register_callback(print_event)
        monitor_task = asyncio.create_task(self.start())

        try:
            await asyncio.sleep(duration_seconds)
        finally:
            self.stop()
            monitor_task.cancel()
            print("\n" + "=" * 70)
            print("  NETWORK MONITOR DEMO COMPLETE")
            print("=" * 70)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    monitor = NetworkMonitor()
    asyncio.run(monitor.run_demo(duration_seconds=10))

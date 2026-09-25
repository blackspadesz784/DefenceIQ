"""DefenceIQ - Process Monitoring Service.

Tracks process creation, parent/child relationships, Authenticode digital
signatures, resource spikes, and suspicious process chains. Emits structured
events to the internal event bus.
"""

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

import psutil

# Configuration import
from sentinellayer.agent.config.settings import ProcessMonitorConfig, default_settings

logger = logging.getLogger("DefenceIQ.ProcessMonitor")

# ============================================================================
# Windows Authenticode & Catalog Signature Verification (ctypes)
# ============================================================================
_SIGNATURE_CACHE: Dict[str, Dict[str, Any]] = {}

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    wintrust = ctypes.windll.wintrust
    kernel32 = ctypes.windll.kernel32

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    # CryptCATAdmin prototypes
    wintrust.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL

    wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_char_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p

    wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

    wintrust.CryptCATAdminReleaseContext.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p

    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL


def verify_file_signature(file_path: Optional[str]) -> Dict[str, Any]:
    """Verifies Authenticode embedded and catalog signatures using native Win32 APIs.

    Results are cached in-memory by file path.
    """
    if not file_path or not os.path.isfile(file_path):
        return {
            "is_signed": False,
            "status": "NOT_FOUND" if file_path else "NO_PATH",
            "signer": None,
        }

    norm_path = os.path.normcase(os.path.abspath(file_path))
    if norm_path in _SIGNATURE_CACHE:
        return _SIGNATURE_CACHE[norm_path]

    if sys.platform != "win32":
        result = {"is_signed": False, "status": "NON_WINDOWS", "signer": None}
        _SIGNATURE_CACHE[norm_path] = result
        return result

    try:
        # Step 1: Verify Embedded Authenticode Signature
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = norm_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        data.dwProvFlags = 0x00000040  # WTD_CACHE_ONLY_URL_RETRIEVAL

        status = ctypes.windll.wintrust.WinVerifyTrust(
            0,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(data),
        )
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        ctypes.windll.wintrust.WinVerifyTrust(
            0,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(data),
        )

        status_u32 = status & 0xFFFFFFFF
        if status_u32 == 0:
            result = {"is_signed": True, "status": "VALID_EMBEDDED", "signer": "Verified Authenticode"}
            _SIGNATURE_CACHE[norm_path] = result
            return result

        # Step 2: If no embedded signature, verify Windows Catalog (CatRoot)
        hCatAdmin = ctypes.c_void_p()
        if wintrust.CryptCATAdminAcquireContext(ctypes.byref(hCatAdmin), None, 0):
            hFile = kernel32.CreateFileW(norm_path, 0x80000000, 1, None, 3, 0, None)
            if hFile and hFile != -1 and hFile != 0xFFFFFFFF:
                cbHash = wintypes.DWORD(0)
                wintrust.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cbHash), None, 0)
                if cbHash.value > 0:
                    pbHash = ctypes.create_string_buffer(cbHash.value)
                    if wintrust.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cbHash), pbHash, 0):
                        kernel32.CloseHandle(hFile)
                        hFile = None
                        hCatInfo = wintrust.CryptCATAdminEnumCatalogFromHash(
                            hCatAdmin, pbHash, cbHash.value, 0, None
                        )
                        if hCatInfo:
                            wintrust.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
                            wintrust.CryptCATAdminReleaseContext(hCatAdmin, 0)
                            result = {"is_signed": True, "status": "VALID_CATALOG", "signer": "Microsoft Windows Catalog"}
                            _SIGNATURE_CACHE[norm_path] = result
                            return result

                if hFile and hFile != -1 and hFile != 0xFFFFFFFF:
                    kernel32.CloseHandle(hFile)
            wintrust.CryptCATAdminReleaseContext(hCatAdmin, 0)

        # Step 3: Map known trust failure codes
        if status_u32 == 0x800B0100:
            status_str = "UNSIGNED"
        elif status_u32 == 0x800B0109:
            status_str = "CERT_UNTRUSTED_ROOT"
        elif status_u32 == 0x800B0101:
            status_str = "CERT_EXPIRED"
        else:
            status_str = f"UNTRUSTED_{hex(status_u32)}"

        result = {"is_signed": False, "status": status_str, "signer": None}
        _SIGNATURE_CACHE[norm_path] = result
        return result

    except Exception as exc:
        logger.debug(f"Signature check exception for {norm_path}: {exc}")
        result = {"is_signed": False, "status": f"ERROR_{type(exc).__name__}", "signer": None}
        _SIGNATURE_CACHE[norm_path] = result
        return result


# ============================================================================
# Structured Event Schema
# ============================================================================
@dataclass
class ProcessEvent:
    """Structured telemetry event emitted for process lifecycle changes."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = "PROCESS_CREATED"  # PROCESS_CREATED, PROCESS_TERMINATED, PROCESS_SPIKE
    pid: int = 0
    ppid: Optional[int] = None
    name: str = ""
    exe: Optional[str] = None
    cmdline: List[str] = field(default_factory=list)
    username: Optional[str] = None
    parent_name: Optional[str] = None
    parent_exe: Optional[str] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    is_signed: bool = False
    signature_status: str = "UNKNOWN"
    signature_signer: Optional[str] = None
    signals: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to standard dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize event to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Process Monitor
# ============================================================================
class ProcessMonitor:
    """Continuously monitors process activity, parent-child lineages,

    binary Authenticode signatures, and resource spikes. Emits events to
    an async Queue or registered callback handlers.
    """

    # Parent processes that should normally not spawn administrative shells
    SUSPICIOUS_PARENTS: Set[str] = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "acrord32.exe",
        "acrobat.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
    }

    def __init__(
        self,
        event_bus: Optional[asyncio.Queue] = None,
        config: Optional[ProcessMonitorConfig] = None,
    ):
        self.event_bus = event_bus
        self.config = config or default_settings.process_monitor
        self.callbacks: List[Callable[[ProcessEvent], None]] = []
        self._running = False
        self._known_processes: Dict[int, Dict[str, Any]] = {}
        self._suspicious_names_lower = {
            name.lower() for name in self.config.suspicious_process_names
        }

    def register_callback(self, callback: Callable[[ProcessEvent], None]):
        """Register a synchronous or asynchronous callback for emitted events."""
        self.callbacks.append(callback)

    def emit_event(self, event: ProcessEvent):
        """Dispatch event to the event queue and all registered callbacks."""
        if self.event_bus is not None:
            try:
                self.event_bus.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Event bus queue full; dropped event %s", event.event_id)

        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Callback error processing event {event.event_id}: {e}")

    def inspect_process(self, proc: psutil.Process) -> Optional[Dict[str, Any]]:
        """Safely extract process metadata, parent info, and resource usage."""
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = None

                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = []

                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = None

                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = None

                # Parent details
                parent_name = None
                parent_exe = None
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name()
                        try:
                            parent_exe = parent.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            parent_exe = None
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Resources
                try:
                    mem_info = proc.memory_info()
                    memory_mb = round(mem_info.rss / (1024 * 1024), 2)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    memory_mb = 0.0

                try:
                    cpu_percent = proc.cpu_percent(interval=None)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu_percent = 0.0

                return {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline,
                    "username": username,
                    "parent_name": parent_name,
                    "parent_exe": parent_exe,
                    "cpu_percent": cpu_percent,
                    "memory_mb": memory_mb,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def evaluate_signals(self, pdata: Dict[str, Any]) -> List[str]:
        """Evaluates behavioral signals for a process according to the risk model."""
        signals = []
        name_lower = pdata["name"].lower()
        parent_lower = (pdata.get("parent_name") or "").lower()

        # 1. Spawned script or administrative shell
        if name_lower in self._suspicious_names_lower:
            signals.append("spawned_script_shell")

        # 2. Suspicious parent-child relationship (e.g. Word or browser launching PowerShell/cmd)
        if parent_lower in self.SUSPICIOUS_PARENTS and name_lower in self._suspicious_names_lower:
            signals.append("suspicious_parent_child")

        # 3. Digital signature checks
        sig_info = verify_file_signature(pdata.get("exe"))
        pdata["signature_info"] = sig_info

        if not sig_info["is_signed"]:
            signals.append("no_valid_digital_signature")
            signals.append("unknown_unsigned_publisher")

        # 4. Resource spikes
        if pdata["cpu_percent"] >= self.config.cpu_spike_threshold_percent:
            signals.append("resource_spike_cpu")
        if pdata["memory_mb"] >= self.config.memory_spike_threshold_mb:
            signals.append("resource_spike_memory")

        return signals

    def initialize_baseline(self):
        """Snapshots all currently running processes to avoid false alert floods on startup."""
        count = 0
        for proc in psutil.process_iter():
            pdata = self.inspect_process(proc)
            if pdata:
                self._known_processes[pdata["pid"]] = pdata
                count += 1
        logger.info(f"Initialized baseline process map with {count} running processes.")

    def scan_iteration(self) -> List[ProcessEvent]:
        """Performs a single snapshot iteration to detect creations, spikes, and terminations."""
        events = []
        current_pids = set()

        for proc in psutil.process_iter():
            pid = proc.pid
            current_pids.add(pid)

            if pid not in self._known_processes:
                # NEW PROCESS DETECTED
                pdata = self.inspect_process(proc)
                if not pdata:
                    continue

                signals = self.evaluate_signals(pdata)
                sig_info = pdata.get("signature_info", {})

                event = ProcessEvent(
                    event_type="PROCESS_CREATED",
                    pid=pdata["pid"],
                    ppid=pdata["ppid"],
                    name=pdata["name"],
                    exe=pdata["exe"],
                    cmdline=pdata["cmdline"],
                    username=pdata["username"],
                    parent_name=pdata["parent_name"],
                    parent_exe=pdata["parent_exe"],
                    cpu_percent=pdata["cpu_percent"],
                    memory_mb=pdata["memory_mb"],
                    is_signed=sig_info.get("is_signed", False),
                    signature_status=sig_info.get("status", "UNKNOWN"),
                    signature_signer=sig_info.get("signer"),
                    signals=signals,
                    metadata={"scanned_at": time.time()},
                )
                self._known_processes[pid] = pdata
                events.append(event)
                self.emit_event(event)

            else:
                # EXISTING PROCESS: Check for Resource Spikes
                if pid == 0:
                    continue

                prev_data = self._known_processes[pid]
                try:
                    cpu = proc.cpu_percent(interval=None)
                    mem_mb = round(proc.memory_info().rss / (1024 * 1024), 2)

                    spike_signals = []
                    if cpu >= self.config.cpu_spike_threshold_percent:
                        spike_signals.append("resource_spike_cpu")
                    if mem_mb >= self.config.memory_spike_threshold_mb:
                        spike_signals.append("resource_spike_memory")

                    if spike_signals:
                        event = ProcessEvent(
                            event_type="PROCESS_SPIKE",
                            pid=pid,
                            ppid=prev_data.get("ppid"),
                            name=prev_data.get("name", ""),
                            exe=prev_data.get("exe"),
                            cmdline=prev_data.get("cmdline", []),
                            username=prev_data.get("username"),
                            parent_name=prev_data.get("parent_name"),
                            parent_exe=prev_data.get("parent_exe"),
                            cpu_percent=cpu,
                            memory_mb=mem_mb,
                            signals=spike_signals,
                            metadata={"previous_cpu": prev_data.get("cpu_percent")},
                        )
                        events.append(event)
                        self.emit_event(event)

                    prev_data["cpu_percent"] = cpu
                    prev_data["memory_mb"] = mem_mb
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        # Check for TERMINATED processes
        terminated_pids = set(self._known_processes.keys()) - current_pids
        for t_pid in terminated_pids:
            old_data = self._known_processes.pop(t_pid, None)
            if old_data:
                term_event = ProcessEvent(
                    event_type="PROCESS_TERMINATED",
                    pid=t_pid,
                    ppid=old_data.get("ppid"),
                    name=old_data.get("name", ""),
                    exe=old_data.get("exe"),
                    cmdline=old_data.get("cmdline", []),
                    username=old_data.get("username"),
                    parent_name=old_data.get("parent_name"),
                    parent_exe=old_data.get("parent_exe"),
                    signals=[],
                )
                events.append(term_event)
                self.emit_event(term_event)

        return events

    async def start(self):
        """Runs the monitoring loop asynchronously until stop() is called."""
        self._running = True
        self.initialize_baseline()
        logger.info(
            f"Process monitor started. Poll interval: {self.config.poll_interval_seconds}s"
        )

        while self._running:
            try:
                self.scan_iteration()
            except Exception as e:
                logger.error(f"Error during process monitor scan iteration: {e}", exc_info=True)

            await asyncio.sleep(self.config.poll_interval_seconds)

    def stop(self):
        """Stops the process monitor loop."""
        self._running = False
        logger.info("Process monitor stopped.")

    async def run_demo(self, duration_seconds: int = 30):
        """Runs a live console demonstration printing structured JSON events."""
        print("=" * 70)
        print("  DEFENCEIQ - PROCESS MONITORING DEMO (Phase 1)")
        print("=" * 70)
        print(f"Monitoring active processes for {duration_seconds} seconds...")
        print("TIP: Open Notepad, Command Prompt, or PowerShell to see live events!")
        print("=" * 70)

        def print_event(event: ProcessEvent):
            print("\n[+] LIVE EVENT CAPTURED:")
            print(event.to_json(indent=2))

        self.register_callback(print_event)
        monitor_task = asyncio.create_task(self.start())

        try:
            await asyncio.sleep(duration_seconds)
        finally:
            self.stop()
            monitor_task.cancel()
            print("\n" + "=" * 70)
            print("  DEMO COMPLETE")
            print("=" * 70)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DefenceIQ Process Monitor Demo")
    parser.add_argument(
        "--demo", action="store_true", default=True, help="Run live console demo"
    )
    parser.add_argument(
        "--duration", type=int, default=20, help="Demo duration in seconds"
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    monitor = ProcessMonitor()
    asyncio.run(monitor.run_demo(duration_seconds=args.duration))

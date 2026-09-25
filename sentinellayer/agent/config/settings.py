"""Agent configuration and settings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class ProtectionLevel(str, Enum):
    BASIC = "basic"
    BALANCED = "balanced"
    MAXIMUM = "maximum"


@dataclass
class RiskWeights:
    """Configurable additive weights for contributing risk signals."""
    unknown_unsigned_publisher: int = 15
    no_valid_digital_signature: int = 10
    spawned_script_shell: int = 20
    created_persistence_autorun: int = 20
    connected_unrecognized_host: int = 15
    modified_encrypted_many_files: int = 20
    attempted_disable_security: int = 25
    ml_anomaly_detected: int = 15


@dataclass
class ProcessMonitorConfig:
    """Process monitoring settings."""
    poll_interval_seconds: float = 1.0
    cpu_spike_threshold_percent: float = 85.0
    memory_spike_threshold_mb: float = 500.0
    suspicious_process_names: List[str] = field(default_factory=lambda: [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "vssadmin.exe",
        "schtasks.exe"
    ])


@dataclass
class FileMonitorConfig:
    """File system monitoring settings."""
    entropy_threshold: float = 7.2
    rapid_modification_threshold: int = 15
    mass_deletion_threshold: int = 10
    mass_encryption_threshold: int = 5
    window_seconds: float = 5.0
    max_entropy_sample_bytes: int = 65536
    executable_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"
    ])
    watch_paths: List[str] = field(default_factory=lambda: [
        # Will be expanded by os.path.expandvars in runtime
        "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Desktop",
        "%USERPROFILE%\\Documents",
        "%TEMP%",
    ])
    sensitive_paths: List[str] = field(default_factory=lambda: [
        "%SystemRoot%\\System32",
        "%SystemRoot%",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ])


@dataclass
class NetworkMonitorConfig:
    """Network connection monitoring settings."""
    poll_interval_seconds: float = 1.0
    known_destinations_file: str = "known_destinations.json"
    suspicious_process_names: List[str] = field(default_factory=lambda: [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "vssadmin.exe",
    ])
    suspicious_destination_ports: List[int] = field(default_factory=lambda: [
        4444, 5555, 6666, 6667, 1337, 31337, 8888, 9999
    ])


@dataclass
class USBMonitorConfig:
    """USB and removable device monitoring settings."""
    poll_interval_seconds: float = 1.0
    scan_on_mount: bool = True
    flag_autorun: bool = True
    executable_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".cpl", ".dll", ".lnk"
    ])


@dataclass
class Settings:
    """Master agent settings."""
    protection_level: ProtectionLevel = ProtectionLevel.BALANCED
    risk_weights: RiskWeights = field(default_factory=RiskWeights)
    process_monitor: ProcessMonitorConfig = field(default_factory=ProcessMonitorConfig)
    file_monitor: FileMonitorConfig = field(default_factory=FileMonitorConfig)
    network_monitor: NetworkMonitorConfig = field(default_factory=NetworkMonitorConfig)
    usb_monitor: USBMonitorConfig = field(default_factory=USBMonitorConfig)
    
    # Comms & Local Server
    host: str = "0.0.0.0"
    port: int = 8765
    pairing_token_file: str = "pairing_token.key"
    db_path: str = "defenceiq.db"
    
    # Thresholds for bands
    green_band_max: int = 30
    yellow_band_max: int = 60
    orange_band_max: int = 80
    red_band_max: int = 100


default_settings = Settings()

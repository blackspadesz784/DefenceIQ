"""DefenceIQ - Rule-Based Risk Scoring Engine.

Calculates explainable 0–100 risk scores using an additive weighted signal model.
Provides detailed signal breakdowns, score bands, and human-readable explanations.
"""

from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional, Tuple

from sentinellayer.agent.config.settings import RiskWeights, Settings, default_settings

logger = logging.getLogger("DefenceIQ.RiskScoring")


@dataclass
class ContributingSignal:
    """Detailed metadata for a signal contributing to an incident score."""
    name: str
    weight: int
    category: str
    description: str


@dataclass
class ScoreResult:
    """Explainable risk scoring result."""
    score: int
    band: str  # GREEN, YELLOW, ORANGE, RED
    contributing_signals: List[ContributingSignal]
    explanation: str
    severity_level: str = "INFORMATION"  # INFORMATION, LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "severity_level": self.severity_level,
            "contributing_signals": [
                {
                    "name": s.name,
                    "weight": s.weight,
                    "category": s.category,
                    "description": s.description,
                }
                for s in self.contributing_signals
            ],
            "explanation": self.explanation,
        }


class RiskScoringEngine:
    """Evaluates accumulated telemetry signals and computes 0-100 risk scores."""

    # Human-readable explanations and categories for each known signal
    SIGNAL_DEFINITIONS: Dict[str, Tuple[str, str]] = {
        "unknown_unsigned_publisher": (
            "IDENTITY",
            "Process executable publisher is unknown or unverified",
        ),
        "no_valid_digital_signature": (
            "INTEGRITY",
            "Binary lacks a valid Authenticode signature or certificate is invalid",
        ),
        "spawned_script_shell": (
            "EXECUTION",
            "Process executed an administrative scripting shell (PowerShell/cmd/wscript/mshta)",
        ),
        "suspicious_parent_child": (
            "EXECUTION",
            "Abnormal parent-child execution (e.g. Office application or browser spawning a shell)",
        ),
        "created_persistence_autorun": (
            "PERSISTENCE",
            "Created autorun, startup item, or persistence registry modification",
        ),
        "sensitive_folder_modification": (
            "SYSTEM",
            "Modified files inside sensitive Windows system or startup folders",
        ),
        "connected_unrecognized_host": (
            "NETWORK",
            "Initiated outbound connection to an unrecognized public external host",
        ),
        "suspicious_process_network_connection": (
            "NETWORK",
            "Scripting shell or administrative tool made an outbound network connection",
        ),
        "network_after_suspicious_process": (
            "CORRELATION",
            "Outbound network activity immediately followed suspicious process behavior",
        ),
        "suspicious_destination_port": (
            "NETWORK",
            "Targeted a common reverse shell, IRC, or C2 communication port",
        ),
        "modified_encrypted_many_files": (
            "IMPACT",
            "Rapid high-entropy file modifications matching ransomware encryption burst",
        ),
        "rapid_file_modifications": (
            "IMPACT",
            "High-frequency file modifications exceeding normal baseline rate",
        ),
        "mass_file_deletions": (
            "IMPACT",
            "High-frequency deletion of multiple files across short time window",
        ),
        "attempted_disable_security": (
            "DEFENSE_EVASION",
            "Attempted to disable Windows Defender, clear event logs, or terminate security agent",
        ),
        "yara_rule_matched": (
            "SIGNATURE",
            "Matched a behavioral YARA rule pattern (reverse shell or ransomware markers)",
        ),
        "known_malicious_hash": (
            "REPUTATION",
            "Cryptographic file hash matches a known malicious threat signature",
        ),
        "virustotal_positive_detection": (
            "REPUTATION",
            "Multiple anti-malware engines on VirusTotal flagged the file as malicious",
        ),
        "clamav_malware_detected": (
            "SIGNATURE",
            "ClamAV signature database identified a known malware strain",
        ),
        "pe_packed_section_detected": (
            "EVASION",
            "Executable contains packed or high-entropy executable sections",
        ),
        "process_injection_apis_imported": (
            "INJECTION",
            "Binary imports low-level process injection and memory tampering APIs",
        ),
        "multiple_suspicious_apis_imported": (
            "STATIC_ANALYSIS",
            "Binary imports multiple APIs commonly abused for evasion or persistence",
        ),
        "resource_spike_cpu": (
            "RESOURCE",
            "Process CPU usage spiked abnormally above threshold",
        ),
        "resource_spike_memory": (
            "RESOURCE",
            "Process memory footprint spiked significantly above normal threshold",
        ),
        "usb_autorun_detected": (
            "PERSISTENCE",
            "Removable media configured with autorun auto-execution payload",
        ),
        "usb_executable_present": (
            "REMOVABLE_MEDIA",
            "Removable storage drive contains binary executables or scripts in root",
        ),
        "usb_device_inserted": (
            "HARDWARE",
            "Removable USB storage device connected to endpoint",
        ),
        "usb_device_removed": (
            "HARDWARE",
            "Removable USB storage device disconnected",
        ),
        "ml_anomaly_detected": (
            "ANOMALY",
            "Unsupervised machine learning model flagged anomalous process telemetry deviations",
        ),
    }

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or default_settings
        self.weights = self.settings.risk_weights

    def get_signal_weight(self, signal_name: str) -> int:
        """Returns the configured weight for a specific signal."""
        # Check core config weights first
        if signal_name == "unknown_unsigned_publisher":
            return self.weights.unknown_unsigned_publisher
        elif signal_name == "no_valid_digital_signature":
            return self.weights.no_valid_digital_signature
        elif signal_name == "spawned_script_shell":
            return self.weights.spawned_script_shell
        elif signal_name in ("created_persistence_autorun", "sensitive_folder_modification", "usb_autorun_detected"):
            return self.weights.created_persistence_autorun
        elif signal_name == "connected_unrecognized_host":
            return self.weights.connected_unrecognized_host
        elif signal_name == "modified_encrypted_many_files":
            return self.weights.modified_encrypted_many_files
        elif signal_name == "attempted_disable_security":
            return self.weights.attempted_disable_security
        elif signal_name == "ml_anomaly_detected":
            return getattr(self.weights, "ml_anomaly_detected", 15)
        # Layered detection & Removable media weights
        elif signal_name in ("known_malicious_hash", "clamav_malware_detected"):
            return 40
        elif signal_name in ("yara_rule_matched", "virustotal_positive_detection"):
            return 25
        elif signal_name in ("suspicious_parent_child", "process_injection_apis_imported"):
            return 20
        elif signal_name in ("suspicious_process_network_connection", "network_after_suspicious_process", "usb_executable_present"):
            return 15
        elif signal_name in ("pe_packed_section_detected", "suspicious_destination_port"):
            return 15
        elif signal_name in ("rapid_file_modifications", "mass_file_deletions", "multiple_suspicious_apis_imported"):
            return 10
        elif signal_name in ("resource_spike_cpu", "resource_spike_memory"):
            return 5
        elif signal_name in ("usb_device_inserted", "usb_device_removed"):
            return 0
        return 5

    def calculate_score(self, signals: List[str]) -> ScoreResult:
        """Calculates 0–100 risk score and returns detailed explainability breakdown."""
        unique_signals = list(dict.fromkeys(signals))  # preserve order, eliminate duplicates
        contributing: List[ContributingSignal] = []
        raw_score = 0

        for sig in unique_signals:
            weight = self.get_signal_weight(sig)
            category, desc = self.SIGNAL_DEFINITIONS.get(
                sig, ("GENERAL", f"Behavioral signal: {sig}")
            )
            raw_score += weight
            contributing.append(
                ContributingSignal(
                    name=sig,
                    weight=weight,
                    category=category,
                    description=desc,
                )
            )

        # Clamped to 0–100
        score = min(max(raw_score, 0), 100)

        # Determine score band and 5-tier severity level
        if score <= self.settings.green_band_max:
            band = "GREEN"
            severity = "INFORMATION" if score < 15 else "LOW"
        elif score <= self.settings.yellow_band_max:
            band = "YELLOW"
            severity = "LOW" if score <= 45 else "MEDIUM"
        elif score <= self.settings.orange_band_max:
            band = "ORANGE"
            severity = "MEDIUM" if score <= 70 else "HIGH"
        else:
            band = "RED"
            severity = "CRITICAL"

        # Generate human-readable explainability narrative
        explanation = self._build_explanation(score, band, contributing)

        return ScoreResult(
            score=score,
            band=band,
            severity_level=severity,
            contributing_signals=contributing,
            explanation=explanation,
        )

    def _build_explanation(
        self, score: int, band: str, contributing: List[ContributingSignal]
    ) -> str:
        """Constructs an explainable summary of the mathematical scoring decision."""
        if not contributing:
            return f"Assigned score {score}/100 ({band}): Normal baseline activity with no suspicious indicators."

        parts = [f"Assigned score {score}/100 ({band}) based on {len(contributing)} contributing signal(s):"]
        for s in contributing:
            parts.append(f"• {s.description} (+{s.weight} pts)")

        if band == "RED":
            parts.append("Verdict: CRITICAL THREAT — Requires immediate process isolation and file quarantine.")
        elif band == "ORANGE":
            parts.append("Verdict: HIGH RISK — Requires network containment and process suspension.")
        elif band == "YELLOW":
            parts.append("Verdict: SUSPICIOUS — Increased monitoring frequency and user notification.")
        else:
            parts.append("Verdict: NORMAL — Activity logged within baseline tolerances.")

        return "\n".join(parts)

# Features — AI-Powered Personal Security Layer

---

## Overview

Features are categorized into three tiers:

- **MVP** — Required for the first working, demonstrable prototype.
- **Phase 2** — Important features to add after the MVP is stable.
- **Advanced / Future** — Valuable but not required for early development stages.

Each feature entry includes: purpose, user benefit, technical dependencies, and priority.

---

## MVP Features

These features define the minimum working system. **No MVP feature may be omitted or deferred.**

---

### F-MVP-01 — Process Monitoring

| Field | Value |
|---|---|
| **Purpose** | Track all running processes on the laptop in near-real time |
| **User Benefit** | Provides visibility into what is running on the computer at any given time — the foundation of all process-based detection |
| **Technical Dependency** | `psutil` library; Process Monitor module |
| **Priority** | Critical |

Collects: PID, parent PID, process name, executable path, command-line arguments, username, start time.
Detects: process creation, process termination, unusual parent-child relationships.

---

### F-MVP-02 — File System Activity Monitoring

| Field | Value |
|---|---|
| **Purpose** | Monitor file creation, modification, deletion, and rename events in user-sensitive directories |
| **User Benefit** | Detects ransomware-like mass file modifications, suspicious file drops, and malicious script creation |
| **Technical Dependency** | `watchdog` library; File Monitor module |
| **Priority** | Critical |

Monitored scope: user home directory, Desktop, Downloads, Documents, AppData/Temp, System32 (read-only).

---

### F-MVP-03 — Network Connection Monitoring

| Field | Value |
|---|---|
| **Purpose** | Monitor active network connections and associate them with processes |
| **User Benefit** | Identifies unexpected outbound connections from unknown or suspicious processes (e.g., C2 communication) |
| **Technical Dependency** | `psutil.net_connections()`; Network Monitor module |
| **Priority** | Critical |

---

### F-MVP-04 — Startup / Persistence Change Detection

| Field | Value |
|---|---|
| **Purpose** | Monitor Windows Registry Run keys and Startup folder for unauthorized changes |
| **User Benefit** | Detects malware attempting to survive reboots by adding persistence mechanisms |
| **Technical Dependency** | `pywin32`, `winreg`; Startup Monitor module |
| **Priority** | Critical |

---

### F-MVP-05 — Script and Command Execution Monitoring

| Field | Value |
|---|---|
| **Purpose** | Monitor invocations of scripting hosts (PowerShell, cmd, WScript, etc.) with their arguments |
| **User Benefit** | Detects encoded PowerShell, download cradles, and other script-based attack techniques |
| **Technical Dependency** | Process Monitor module; command feature extraction |
| **Priority** | Critical |

---

### F-MVP-06 — Feature Extraction Pipeline

| Field | Value |
|---|---|
| **Purpose** | Transform raw telemetry events into normalized, structured feature vectors for detection |
| **User Benefit** | Enables both rule-based and AI-based detection to work from a consistent, structured data representation |
| **Technical Dependency** | Monitoring modules; `pandas`, `numpy` |
| **Priority** | Critical |

---

### F-MVP-07 — Rule-Based Detection Engine

| Field | Value |
|---|---|
| **Purpose** | Evaluate structured telemetry against a curated set of detection rules |
| **User Benefit** | Provides deterministic, explainable detection for known suspicious patterns without requiring ML |
| **Technical Dependency** | Feature extractor; YAML rule files |
| **Priority** | Critical |

Initial ruleset covers: PowerShell encoded execution, suspicious parent-child processes, persistence modifications, mass file events, processes on unusual ports.

---

### F-MVP-08 — AI Anomaly Detection

| Field | Value |
|---|---|
| **Purpose** | Detect behavioral anomalies that do not match known rules but deviate from normal system behavior |
| **User Benefit** | Provides a second layer of detection for novel or unfamiliar threats; increases confidence when combined with rule signals |
| **Technical Dependency** | Feature extractor; `scikit-learn` Isolation Forest model; model artifact |
| **Priority** | High |

> **Important:** AI anomaly score is one input into risk scoring — a high score alone does not trigger an alert.

---

### F-MVP-09 — Risk Scoring

| Field | Value |
|---|---|
| **Purpose** | Maintain a real-time, composite risk score (0–100) for the device based on detection signals |
| **User Benefit** | Provides a single, understandable metric for the device's current security posture |
| **Technical Dependency** | Rule engine output; AI anomaly score; Risk Scorer module |
| **Priority** | Critical |

Score decays over time without new suspicious signals. Maps to: Low / Medium / High / Critical severity bands.

---

### F-MVP-10 — Alert Generation

| Field | Value |
|---|---|
| **Purpose** | Generate structured, contextualized security alerts when thresholds are crossed |
| **User Benefit** | Informs the user about detected suspicious behavior with context — what happened, when, and why it was flagged |
| **Technical Dependency** | Risk Scorer; Alert Manager; local SQLite storage |
| **Priority** | Critical |

Includes alert deduplication to suppress repeated alerts for the same ongoing event.

---

### F-MVP-11 — Local Event Storage

| Field | Value |
|---|---|
| **Purpose** | Persist all security events, alerts, and risk score history on the laptop |
| **User Benefit** | Ensures no data is lost if the backend is unreachable; provides local audit trail |
| **Technical Dependency** | SQLite; agent storage module |
| **Priority** | Critical |

---

### F-MVP-12 — Offline Monitoring Mode

| Field | Value |
|---|---|
| **Purpose** | Continue all monitoring and detection without internet connectivity |
| **User Benefit** | Security monitoring is never dependent on cloud availability; the agent is always on |
| **Technical Dependency** | Local SQLite; Sync Manager (offline detection); all monitoring and detection modules |
| **Priority** | Critical |

---

### F-MVP-13 — Event Synchronization

| Field | Value |
|---|---|
| **Purpose** | Synchronize locally queued events to the backend when connectivity is restored |
| **User Benefit** | No security events are lost during offline periods; the mobile dashboard reflects complete history |
| **Technical Dependency** | Sync Manager; API client; backend event ingestion endpoint |
| **Priority** | Critical |

---

### F-MVP-14 — Backend REST API

| Field | Value |
|---|---|
| **Purpose** | Provide a central server to receive events from the agent and serve data to the mobile app |
| **User Benefit** | Enables remote monitoring and multi-session access to security data |
| **Technical Dependency** | FastAPI; PostgreSQL; SQLAlchemy |
| **Priority** | Critical |

---

### F-MVP-15 — User Authentication

| Field | Value |
|---|---|
| **Purpose** | Authenticate users and agents with the backend using JWT |
| **User Benefit** | Ensures only the authorized user can view their device's security data |
| **Technical Dependency** | FastAPI auth module; JWT; bcrypt |
| **Priority** | Critical |

---

### F-MVP-16 — Device Registration

| Field | Value |
|---|---|
| **Purpose** | Register the laptop agent as a device associated with the user's account |
| **User Benefit** | Links the laptop's security events to the correct user account in the mobile dashboard |
| **Technical Dependency** | Backend device registration endpoint; agent sync module |
| **Priority** | Critical |

---

### F-MVP-17 — Android Mobile Dashboard

| Field | Value |
|---|---|
| **Purpose** | Display the device's security status, current risk score, and recent security events on the user's Android phone |
| **User Benefit** | Remote visibility into the laptop's security posture at any time |
| **Technical Dependency** | Flutter; backend REST API; JWT authentication |
| **Priority** | Critical |

Screens: Dashboard, Alerts, Event Detail, Security History.

---

### F-MVP-18 — Push Notifications for High-Severity Alerts

| Field | Value |
|---|---|
| **Purpose** | Deliver real-time push notifications to the Android app when Critical or High severity alerts are generated |
| **User Benefit** | Immediate awareness of potential threats even when the app is closed |
| **Technical Dependency** | FCM (Firebase Cloud Messaging); backend notification service |
| **Priority** | High |

---

### F-MVP-19 — Risk Score History Chart

| Field | Value |
|---|---|
| **Purpose** | Display the risk score trend over time in the mobile app |
| **User Benefit** | Allows the user to see whether their device's security posture has been improving or degrading over time |
| **Technical Dependency** | Backend risk score storage; Flutter charting widget |
| **Priority** | Medium |

---

### F-MVP-20 — Heartbeat / Device Status

| Field | Value |
|---|---|
| **Purpose** | The agent sends periodic heartbeats so the backend knows the device is online |
| **User Benefit** | The mobile dashboard can distinguish between "device is safe" and "device is offline/unreachable" |
| **Technical Dependency** | Sync Manager; backend device status endpoint |
| **Priority** | High |

---

## Phase 2 Features

Features to develop after the MVP is complete and working.

---

### F-P2-01 — Alert Acknowledgement (Mobile)

| Field | Value |
|---|---|
| **Purpose** | Allow the user to acknowledge or dismiss alerts from the mobile app |
| **User Benefit** | Reduces alert noise; allows the user to signal they are aware of and have reviewed an event |
| **Technical Dependency** | Mobile UI; backend alert update endpoint |

---

### F-P2-02 — User-Initiated Process Termination

| Field | Value |
|---|---|
| **Purpose** | Allow the user to trigger process termination for a flagged process via the mobile app |
| **User Benefit** | Gives the user a controlled response option without waiting for the desktop |
| **Technical Dependency** | Mobile UI action; backend action endpoint; agent response engine (currently logs only) |

---

### F-P2-03 — Windows Event Log Integration

| Field | Value |
|---|---|
| **Purpose** | Collect security-relevant events from the Windows Security Event Log |
| **User Benefit** | Adds login events, privilege escalation, and audit failures to the detection dataset |
| **Technical Dependency** | `pywin32` Event Log API |

---

### F-P2-04 — DNS Query Monitoring

| Field | Value |
|---|---|
| **Purpose** | Monitor DNS queries made by processes for C2 domain detection |
| **User Benefit** | Provides a signal for domain-based threat intelligence and C2 communication patterns |
| **Technical Dependency** | Windows DNS API or network-level DNS capture |

---

### F-P2-05 — Supervised Threat Classification (ML)

| Field | Value |
|---|---|
| **Purpose** | Replace or augment Isolation Forest with a supervised classifier trained on labeled threat data |
| **User Benefit** | More accurate classification of specific threat categories (ransomware, keylogger, C2 communication) |
| **Technical Dependency** | Labeled training dataset; XGBoost or Random Forest model; retraining pipeline |

---

### F-P2-06 — Event Filtering in Mobile History

| Field | Value |
|---|---|
| **Purpose** | Allow filtering of security history by date range, severity, and event type |
| **User Benefit** | Makes large event histories navigable |
| **Technical Dependency** | Backend filter query parameters; Flutter filter UI |

---

### F-P2-07 — Remote Rule Updates

| Field | Value |
|---|---|
| **Purpose** | Allow the backend to push updated detection rules to the agent |
| **User Benefit** | New detection rules can be deployed without manually updating the agent on the laptop |
| **Technical Dependency** | Backend rule management endpoint; agent configuration hot-reload |

---

### F-P2-08 — Threat Intelligence Integration

| Field | Value |
|---|---|
| **Purpose** | Cross-reference detected IPs, file hashes, and domains against public threat intelligence feeds |
| **User Benefit** | Increases detection confidence when a process communicates with a known malicious IP or uses a known malicious hash |
| **Technical Dependency** | VirusTotal API or AbuseIPDB API; backend enrichment service |

---

## Advanced / Future Features

Features for long-term development that should not be attempted before Phase 2 is complete.

| Feature | Description | Benefit |
|---|---|---|
| **macOS agent support** | Extend monitoring to macOS using platform-specific APIs | Broader platform coverage |
| **Linux agent support** | Extend monitoring to Ubuntu/Debian Linux | Developer-focused use case |
| **File quarantine** | Move flagged files to an isolated directory | Automated conservative response |
| **Network connection blocking** | Block specific connections via Windows Firewall API | Direct network defense |
| **YARA rule integration** | Support YARA rules for file-based malware detection | Community ruleset compatibility |
| **Web dashboard** | Browser-based alternative to the mobile app | Desktop remote monitoring |
| **iOS dashboard** | iOS version of the mobile app | Apple device support |
| **Multi-device support** | Monitor multiple laptops from one account | Household or small team use |
| **Cloud AI inference** | Send anonymized features to a cloud AI for enhanced analysis | More powerful detection without local GPU |
| **Vulnerability scanning** | Check software versions against CVE databases | Proactive patch awareness |
| **Model retraining on personal baseline** | Continuously update the anomaly model on the user's own system behavior | Reduced false positives |
| **Sandbox integration** | Submit suspicious files to a sandbox API (e.g., VirusTotal) | Dynamic malware analysis |

---

*Document version: 1.0 | Last updated: 2026-09-16*

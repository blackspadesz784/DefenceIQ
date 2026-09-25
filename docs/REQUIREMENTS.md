# Requirements — AI-Powered Personal Security Layer

---

## Overview

This document defines the complete set of functional, non-functional, hardware, software, and operational requirements for the AI-Powered Personal Security Layer.

Requirements are labelled with a priority and MVP flag:

- **[MVP]** — Required for the first working prototype.
- **[P2]** — Target for Phase 2, after a working MVP.
- **[FUTURE]** — Desirable but does not block early development.
- **[MUST]** / **[SHOULD]** / **[COULD]** follow standard MoSCoW prioritization.

---

## 1. Functional Requirements

### 1.1 Laptop Monitoring

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-LM-01 | The agent MUST run as a background process on the user's laptop without requiring the user to manually trigger monitoring. | MUST | ✅ |
| FR-LM-02 | The agent MUST consume minimal CPU and memory during normal operation. | MUST | ✅ |
| FR-LM-03 | The agent MUST survive system startup and re-register itself automatically. | MUST | ✅ |
| FR-LM-04 | The agent SHOULD support graceful shutdown without leaving residual state. | SHOULD | ✅ |
| FR-LM-05 | The agent MUST support a configuration file that defines monitoring scope and thresholds. | MUST | ✅ |
| FR-LM-06 | The agent MUST log its own operational events (startup, errors, restarts) separately from security events. | MUST | ✅ |

---

### 1.2 Security Telemetry Collection

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-TC-01 | The agent MUST monitor all currently running processes and capture: process name, PID, parent PID, user, executable path, command-line arguments, start time. | MUST | ✅ |
| FR-TC-02 | The agent MUST monitor process creation and termination events in near-real time. | MUST | ✅ |
| FR-TC-03 | The agent MUST monitor file system activity in selected directories: creation, modification, deletion, rename of files. | MUST | ✅ |
| FR-TC-04 | The agent MUST monitor active network connections: local port, remote IP, remote port, protocol, owning process. | MUST | ✅ |
| FR-TC-05 | The agent MUST monitor changes to Windows startup locations: registry Run keys, Startup folder, scheduled tasks. | MUST | ✅ |
| FR-TC-06 | The agent MUST monitor script and command execution: PowerShell, cmd, WScript, CScript invocations with arguments. | MUST | ✅ |
| FR-TC-07 | The agent SHOULD monitor process injection indicators: unusual parent-child process relationships. | SHOULD | ✅ |
| FR-TC-08 | The agent SHOULD capture file hashes (SHA-256) for newly created or modified executable files. | SHOULD | ✅ |
| FR-TC-09 | The agent COULD monitor Windows Event Log for security-relevant events (login events, privilege escalation). | COULD | ❌ [P2] |
| FR-TC-10 | The agent COULD monitor DNS queries made by processes. | COULD | ❌ [P2] |
| FR-TC-11 | All collected telemetry MUST be timestamped with UTC time. | MUST | ✅ |
| FR-TC-12 | Telemetry collection MUST NOT capture the content of user documents, emails, or private files. | MUST | ✅ |

---

### 1.3 Feature Extraction

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-FE-01 | Raw telemetry events MUST be normalized into structured feature vectors before passing to the detection engine. | MUST | ✅ |
| FR-FE-02 | Feature extraction MUST compute behavioral features: file-modification rate, network connection frequency, new process rate per time window. | MUST | ✅ |
| FR-FE-03 | Feature extraction MUST extract process relationship features: parent process type, depth of process tree. | MUST | ✅ |
| FR-FE-04 | Feature extraction MUST extract executable metadata: known/unknown binary, signed/unsigned, path legitimacy score. | SHOULD | ✅ |
| FR-FE-05 | Feature extraction SHOULD compute time-based features: time-of-day for process creation, unusual activity hours. | SHOULD | ❌ [P2] |

---

### 1.4 Rule-Based Detection

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-RB-01 | The detection engine MUST include a rule-based component with a curated initial ruleset. | MUST | ✅ |
| FR-RB-02 | Rules MUST be defined in a configurable, human-readable format (YAML or JSON). | MUST | ✅ |
| FR-RB-03 | Rules MUST be independently enabled/disabled without restarting the agent. | SHOULD | ✅ |
| FR-RB-04 | The ruleset MUST include detection patterns for: suspicious PowerShell execution, unusual process parent-child relationships, persistence key modifications, mass file modifications, processes connecting to unusual ports. | MUST | ✅ |
| FR-RB-05 | Rules SHOULD support compound conditions (multiple signals required to trigger). | SHOULD | ✅ |
| FR-RB-06 | Rule hits MUST be logged with the rule ID, matched telemetry, and timestamp. | MUST | ✅ |
| FR-RB-07 | The system MUST support adding new rules without code changes. | SHOULD | ✅ |

---

### 1.5 AI-Based Detection

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-AI-01 | The AI component MUST complement rule-based detection, not replace it. | MUST | ✅ |
| FR-AI-02 | The MVP AI model MUST implement anomaly detection on process and behavioral features. | MUST | ✅ |
| FR-AI-03 | The AI model MUST produce a numerical anomaly score (0.0–1.0) for each evaluated event or feature window. | MUST | ✅ |
| FR-AI-04 | The AI model MUST run inference locally on the laptop — no cloud inference in the MVP. | MUST | ✅ |
| FR-AI-05 | AI inference MUST NOT block telemetry collection or rule-based detection. | MUST | ✅ |
| FR-AI-06 | The AI model SHOULD be replaceable or updateable without modifying the detection pipeline. | SHOULD | ✅ |
| FR-AI-07 | AI anomaly scores MUST be combined with rule-based signals in the risk scoring module. | MUST | ✅ |
| FR-AI-08 | A more advanced supervised classification model SHOULD be trained in Phase 2 using labeled data. | SHOULD | ❌ [P2] |

---

### 1.6 Risk Scoring

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-RS-01 | The system MUST maintain a real-time risk score (0–100) for the device. | MUST | ✅ |
| FR-RS-02 | The risk score MUST combine: rule-based detection results, AI anomaly scores, number and severity of active events. | MUST | ✅ |
| FR-RS-03 | The risk score MUST decay over time as suspicious events age without new signals. | SHOULD | ✅ |
| FR-RS-04 | Risk score thresholds MUST map to severity categories: Low (0–30), Medium (31–60), High (61–85), Critical (86–100). | MUST | ✅ |
| FR-RS-05 | Risk score history MUST be persisted for trend analysis. | MUST | ✅ |

---

### 1.7 Alert Generation

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-AG-01 | The system MUST generate a structured alert when the risk score crosses a configured threshold. | MUST | ✅ |
| FR-AG-02 | Each alert MUST contain: alert ID, timestamp, severity level, triggering event(s), rule ID if applicable, AI anomaly score if applicable, risk score at time of alert, device ID. | MUST | ✅ |
| FR-AG-03 | Alerts MUST be stored locally in case the backend is unreachable. | MUST | ✅ |
| FR-AG-04 | Alerts MUST be transmitted to the backend when connectivity is available. | MUST | ✅ |
| FR-AG-05 | Duplicate or near-duplicate alerts for the same ongoing event MUST be suppressed (deduplication). | SHOULD | ✅ |
| FR-AG-06 | The mobile application MUST receive push or polling notifications for high-severity alerts. | MUST | ✅ |

---

### 1.8 Backend Communication

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-BC-01 | The agent MUST communicate with the backend over HTTPS. | MUST | ✅ |
| FR-BC-02 | The agent MUST authenticate with the backend using a device token (JWT or API key). | MUST | ✅ |
| FR-BC-03 | The agent MUST send security events and alerts to the backend in near-real time when online. | MUST | ✅ |
| FR-BC-04 | The agent MUST queue events locally when the backend is unreachable and retry on reconnection. | MUST | ✅ |
| FR-BC-05 | The agent MUST periodically send a heartbeat to the backend to indicate it is active. | MUST | ✅ |
| FR-BC-06 | The agent SHOULD receive rule/configuration updates from the backend. | SHOULD | ❌ [P2] |

---

### 1.9 Mobile Dashboard

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-MD-01 | The mobile app MUST display the current risk score of each registered device. | MUST | ✅ |
| FR-MD-02 | The mobile app MUST display the device's current online/offline status. | MUST | ✅ |
| FR-MD-03 | The mobile app MUST display a list of recent security events with timestamp, severity, and description. | MUST | ✅ |
| FR-MD-04 | The mobile app MUST display active alerts and their severity. | MUST | ✅ |
| FR-MD-05 | The mobile app MUST display actions taken by the agent (if any). | SHOULD | ✅ |
| FR-MD-06 | The mobile app MUST support push notifications for Critical and High severity alerts. | MUST | ✅ |
| FR-MD-07 | The mobile app MUST allow the user to view full details of a security event. | MUST | ✅ |
| FR-MD-08 | The mobile app MUST display risk score history as a chart. | SHOULD | ✅ |
| FR-MD-09 | The mobile app SHOULD allow the user to acknowledge/dismiss an alert. | SHOULD | ❌ [P2] |
| FR-MD-10 | The mobile app COULD allow the user to trigger a manual scan request. | COULD | ❌ [P2] |
| FR-MD-11 | The mobile app MUST support secure login with JWT authentication. | MUST | ✅ |

---

### 1.10 Security History

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-SH-01 | The backend MUST persist all security events, alerts, and risk scores with timestamps. | MUST | ✅ |
| FR-SH-02 | The mobile app MUST allow the user to browse historical security events. | MUST | ✅ |
| FR-SH-03 | Historical events MUST be filterable by date range and severity. | SHOULD | ❌ [P2] |
| FR-SH-04 | Security events MUST be retained for at least 30 days in the MVP. | SHOULD | ✅ |

---

### 1.11 Controlled Response Mechanisms

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-CR-01 | The agent MUST NOT automatically kill or block processes without a confirmation mechanism. | MUST | ✅ |
| FR-CR-02 | The agent SHOULD be able to log a response action (e.g., "process flagged for user review") and report it to the backend. | SHOULD | ✅ |
| FR-CR-03 | Process termination SHOULD only occur after user-initiated confirmation via the mobile app (future phase). | SHOULD | ❌ [P2] |
| FR-CR-04 | File quarantine (move to isolated directory) SHOULD be supported with a manual trigger. | COULD | ❌ [FUTURE] |
| FR-CR-05 | Network connection blocking SHOULD be supported through host-level firewall rules with explicit user approval. | COULD | ❌ [FUTURE] |
| FR-CR-06 | All response actions MUST be logged with timestamp, action type, target, and user/system attribution. | MUST | ✅ |

---

### 1.12 Offline Behavior

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-OB-01 | All telemetry collection and detection MUST continue when the laptop has no internet access. | MUST | ✅ |
| FR-OB-02 | The agent MUST store security events locally when offline. | MUST | ✅ |
| FR-OB-03 | The agent MUST maintain and update the local risk score when offline. | MUST | ✅ |
| FR-OB-04 | The agent MUST NOT degrade core security monitoring because the backend is unreachable. | MUST | ✅ |
| FR-OB-05 | The mobile dashboard MUST display the last-known device status when it cannot reach the backend. | SHOULD | ✅ |

---

### 1.13 Synchronization

| ID | Requirement | Priority | MVP |
|---|---|---|---|
| FR-SY-01 | When internet connectivity is restored, the agent MUST transmit all queued events to the backend in chronological order. | MUST | ✅ |
| FR-SY-02 | Synchronization MUST be performed without duplicating events already transmitted. | MUST | ✅ |
| FR-SY-03 | Synchronization failures MUST be retried with exponential backoff. | SHOULD | ✅ |
| FR-SY-04 | The agent MUST report the time range of offline events when synchronizing. | SHOULD | ✅ |

---

## 2. Non-Functional Requirements

### 2.1 Performance

| ID | Requirement |
|---|---|
| NFR-P-01 | The agent MUST use less than 2% average CPU on an idle system. |
| NFR-P-02 | The agent MUST use less than 150 MB of RAM during normal operation. |
| NFR-P-03 | The agent MUST NOT introduce noticeable latency to the user's normal computer usage. |
| NFR-P-04 | AI inference per event window MUST complete in under 100 ms on target hardware. |
| NFR-P-05 | Backend API endpoints MUST respond in under 500 ms under normal load. |

### 2.2 Reliability

| ID | Requirement |
|---|---|
| NFR-R-01 | The agent MUST automatically restart if it crashes, using the OS service manager. |
| NFR-R-02 | The agent MUST not lose locally queued events in the event of an unexpected restart. |
| NFR-R-03 | The backend MUST handle agent unavailability gracefully without losing already-received data. |

### 2.3 Scalability

| ID | Requirement |
|---|---|
| NFR-SC-01 | The backend MUST support at least one monitored device per user account in the MVP. |
| NFR-SC-02 | The architecture SHOULD support multiple devices per user in a future phase without redesign. |
| NFR-SC-03 | The database schema MUST be designed to support multi-device queries efficiently. |

### 2.4 Security

| ID | Requirement |
|---|---|
| NFR-SE-01 | All communication between agent and backend MUST use TLS 1.2 or higher. |
| NFR-SE-02 | All API endpoints MUST require authentication. |
| NFR-SE-03 | Agent credentials MUST be stored securely using the OS credential store or equivalent. |
| NFR-SE-04 | The backend MUST validate and sanitize all incoming data from agents. |
| NFR-SE-05 | JWT tokens MUST have a defined expiry and support refresh. |

### 2.5 Privacy

| ID | Requirement |
|---|---|
| NFR-PV-01 | The system MUST NOT collect the content of user files, emails, or documents. |
| NFR-PV-02 | The system MUST NOT capture screenshots or keystrokes. |
| NFR-PV-03 | The system MUST collect only the minimum telemetry required for security analysis. |
| NFR-PV-04 | Users MUST be informed of what data is collected during agent setup. |

### 2.6 Maintainability

| ID | Requirement |
|---|---|
| NFR-M-01 | The codebase MUST follow consistent style guidelines with linting enforced. |
| NFR-M-02 | Detection rules MUST be configurable without modifying source code. |
| NFR-M-03 | The AI model MUST be replaceable without breaking the detection pipeline. |
| NFR-M-04 | All modules MUST have documented public interfaces. |

### 2.7 Usability

| ID | Requirement |
|---|---|
| NFR-U-01 | The mobile dashboard MUST be usable by a non-technical user for basic monitoring. |
| NFR-U-02 | Security alerts MUST use plain language to describe what was detected and why it matters. |
| NFR-U-03 | The agent MUST operate silently in the background without requiring user interaction during normal operation. |

### 2.8 Availability

| ID | Requirement |
|---|---|
| NFR-AV-01 | The laptop agent MUST be available 24/7 regardless of backend connectivity. |
| NFR-AV-02 | The backend SHOULD target 99% uptime for the hackathon demo environment. |

---

## 3. Hardware Requirements

| Component | Minimum Specification |
|---|---|
| Laptop/Desktop CPU | Any modern dual-core CPU (Intel Core i5 7th gen+ or equivalent) |
| Laptop RAM | 4 GB minimum; 8 GB recommended |
| Laptop Storage | 500 MB free for agent, local database, and event queue |
| Backend Server | 1 vCPU, 1 GB RAM minimum (2 GB recommended) |
| Mobile Device | Android 9.0 or higher, 2 GB RAM |

---

## 4. Software Requirements

| Component | Requirement |
|---|---|
| Agent OS | Windows 10 (64-bit) or Windows 11 |
| Agent Runtime | Python 3.10+ |
| Backend | Python 3.10+, FastAPI, PostgreSQL 14+ |
| Mobile App | Flutter 3.x, Android SDK 28+ |
| AI/ML Runtime | scikit-learn, numpy, pandas (local inference) |
| Configuration | YAML-based configuration files |

---

## 5. Supported Operating Systems

| Platform | Status |
|---|---|
| Windows 10 (64-bit) | ✅ MVP target |
| Windows 11 (64-bit) | ✅ MVP target |
| macOS 13+ | ❌ Future phase |
| Ubuntu 22.04 LTS | ❌ Future phase |
| Android 9.0+ | ✅ Mobile dashboard |

---

## 6. Permissions Required

### Laptop Agent

| Permission | Reason |
|---|---|
| Read running processes | Core monitoring |
| Read process command-line arguments | Suspicious script detection |
| Read file system metadata | File activity monitoring |
| Read network connection table | Network monitoring |
| Read Windows registry | Persistence/startup monitoring |
| Write to local database | Event storage |
| Outbound HTTPS to backend | Event transmission |
| Register as Windows service (optional) | Autostart on boot |

> **Note:** The agent MUST NOT require kernel-level drivers in the MVP. All monitoring MUST be achievable from userspace APIs.

### Mobile Application

| Permission | Reason |
|---|---|
| Internet access | Backend API communication |
| Receive push notifications | Alert delivery |
| No access to camera, contacts, location, or storage | Not required |

---

## 7. Network Requirements

| Requirement | Detail |
|---|---|
| Protocol | HTTPS (TLS 1.2+) |
| Ports | 443 (HTTPS), backend-defined port for development |
| Connectivity | Required for backend sync and mobile dashboard; NOT required for core agent monitoring |
| Bandwidth | Low — only structured JSON events and heartbeats transmitted |
| Firewall | Backend must be reachable from agent's network; no inbound port requirements on agent side |

---

## 8. Resource Constraints

| Constraint | Target |
|---|---|
| Agent CPU usage (idle) | < 2% |
| Agent CPU usage (active detection) | < 10% peak |
| Agent RAM | < 150 MB |
| Agent local storage | < 500 MB |
| Event queue size | Up to 10,000 events stored locally before oldest are rotated |
| AI inference time | < 100 ms per feature window |

---

*Document version: 1.0 | Last updated: 2026-09-16*

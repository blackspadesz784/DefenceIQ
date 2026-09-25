# DefenceIQ: Real-Time Laptop Security Monitoring System Connected to Mobile Application

## Executive Summary & Architecture Overview

**DefenceIQ** is an enterprise-grade endpoint detection and real-time mobile security telemetry system designed for continuous laptop-to-mobile monitoring. The architecture delivers seamless real-time visibility and threat containment **without requiring static IP addresses, DDNS, port forwarding, or inbound firewall exceptions**.

The system adheres strictly to the **Principle of Least Privilege and Zero Content Exfiltration**: telemetry is restricted to structural metadata (process names, window titles, domains, entropy values, file paths, and hashes). Under no circumstances are passwords, form inputs, raw document contents, keystrokes, camera feeds, or browser cookies collected or transmitted.

```mermaid
graph TD
    subgraph "Monitored Laptop (Endpoint)"
        A[Process / Window / File / Download Monitors] --> B[AI Correlator & 5-Tier Threat Scorer]
        B --> C[Response Engine & Safe Rollback]
        B --> D[Local SQLite DB]
        B --> E[Cloud Relay Client / Local Server]
        E --> F[Offline Event Buffer (Queue 100)]
    end

    subgraph "Secure Transport Layer"
        E -->|Outbound HTTPS / HMAC-SHA256| G[Encrypted Relay: ntfy.sh]
        E -->|Direct LAN REST / WebSocket| H[Local Wi-Fi Network]
    end

    subgraph "Paired Mobile Client"
        G -->|SSE Stream / Push Alerts| I[Mobile Dashboard & Companion App]
        H -->|Zero-Latency Sync| I
        I -->|Authenticated Commands: ROLLBACK, CONTAIN, UNPAIR| G
    end
```

---

## 1. Secure Token-Based Pairing & IP Independence

### How It Works
1. **Pairing Token Generation**: The agent generates or accepts a human-readable 8-to-12 character token formatted as `DIQ-XXXX-XXXX` (stored securely in `pairing_token.key`).
2. **Deterministic Cryptographic Channel Derivation**:
   Both the laptop agent and mobile client apply HMAC-SHA256 to the normalized token to derive isolated communication channels:
   - **Downlink Topic** (Laptop $\rightarrow$ Mobile): `diq_down_{HMAC(Token, 'DEFENCEIQ_DOWNLINK_V2')[:20]}`
   - **Uplink Topic** (Mobile $\rightarrow$ Laptop): `diq_up_{HMAC(Token, 'DEFENCEIQ_UPLINK_V2')[:20]}`
   - **Shared HMAC Secret**: `HMAC(Token, 'DEFENCEIQ_AUTH_KEY_V2')`
3. **No Inbound Open Ports Required**: The laptop opens an outbound TLS long-poll/SSE stream. When the laptop or phone changes Wi-Fi networks, cellular data, or geographic locations, the connection persists transparently via the relay channels.
4. **Token Rotation & Revocation**:
   - The user can rotate the pairing token at any time via `POST /rotate-token` or from the mobile dashboard.
   - When rotated, a signed `TOKEN_ROTATED` envelope informs the mobile client, and older credentials are decommissioned.
   - Revocation terminates relay subscriptions and clears stored keys.
5. **Local Event Buffering**: If internet connectivity is interrupted, the laptop agent queues up to 100 security events in an in-memory buffer (`_offline_buffer`). Upon reconnection, the queue is flushed to the mobile application in sequence.

---

## 2. Core Functional Modules

### 1. Active Windows and Browser Tabs (`window_monitor.py`)
- **Telemetry Collected**: Application name (e.g. `chrome.exe`, `Code.exe`), browser name, active tab title, domain/host being accessed (e.g. `github.com`), start time, and active duration in seconds.
- **Privacy Engine**: Active regex redactor suppresses sensitive window titles (e.g. password managers, banking pages, private messages, incognito sessions). Tab and process contents are never read.

### 2. Laptop Online / Offline / Sleep Status (`cloud_relay.py` & `main.py`)
- **Heartbeat & Ticker**: The agent periodically emits authenticated `STATUS_UPDATE` payloads with ISO-8601 timestamps.
- **Sleep & Hibernation Detection**: The heartbeat thread monitors time deltas. If an iteration delta exceeds 15 seconds, a sleep/hibernation event is recorded, followed by an immediate `ONLINE` announcement upon wake.
- **Clean Shutdown**: System trap signals (`SIGINT`, `SIGTERM`) dispatch a `SYSTEM_STATE` payload (`SHUTDOWN`) before process exit.
- **Offline Indication**: If heartbeats cease, the mobile app flags the laptop as **OFFLINE** and calculates the exact elapsed time since the last seen timestamp.

### 3. Download Monitoring & Layered Scanning (`download_monitor.py`)
- Intercepts newly downloaded files in the user's `Downloads` folder using filesystem observers.
- Inspects Windows Alternate Data Streams (`Zone.Identifier`) to discover origin URL and host domain (e.g. `malicious-domain.com`).
- Performs instant multi-layered inspection:
  - File extension & MIME type checks.
  - File size and SHA-256 hash calculation.
  - Shannon entropy evaluation (detecting encrypted payloads / packed binaries).
  - YARA rule matching & signature matching.
- Transmits download telemetry and verdict (`CLEAN`, `SUSPICIOUS`, or `MALICIOUS`) without transmitting file contents.

### 4. New Files, Folders & Modification Tracking (`file_monitor.py`)
- Monitors authorized paths (`Documents`, `Desktop`, `Downloads`, `Projects`).
- Detects `FileCreated`, `FileDeleted`, `FileModified`, `FileMoved`, `DirCreated`, and `DirDeleted`.
- **Process Attribution**: Correlates file write operations with the foreground or background process handle responsible.
- **Rolling Window Burst Detection**: Tracks file modification frequencies. A burst exceeding 10 files in 3 seconds triggers rapid modification warnings.

### 5. Suspicious Activity & Threat Classification (`ai_engine.py`)
Multi-signal correlation engine evaluating 5 severity tiers:

| Severity Level | Risk Score | Sample Trigger | Automated Action |
| :--- | :---: | :--- | :--- |
| **CRITICAL** | 85 - 100 | Mass file modification (ransomware burst), rapid entropy jump | Process suspended, Red Alert push, one-tap rollback |
| **HIGH** | 70 - 84 | Suspicious script execution (`powershell -enc`), unknown binary | High-priority push alert, network containment option |
| **MEDIUM** | 50 - 69 | Unrecognized external connection, abnormal resource spike | Warning notification, monitoring frequency doubled |
| **LOW** | 20 - 49 | Minor ML anomaly, unmonitored path access | Logged to database, displayed on dashboard feed |
| **INFORMATION** | 0 - 19 | Baseline application launch, authorized file edit | Recorded for behavioral baseline |

### 6. Real-Time Push Alerts & 🔴 RED ALERT Modal
Critical alerts dispatch a high-priority push notification formatted as:
```
🔴 CRITICAL SECURITY ALERT
Mass File Modification Detected

Process: Unknown Application (PID 4820)
Affected Folder: Documents/Projects
Files Modified: 247
Time: 10:42 PM
Risk: Possible ransomware-like activity
Recommended Action: Automatic process containment executed. One-tap rollback available.
```
Interactive responses available directly from the mobile UI:
1. **Acknowledge**: Marks incident as acknowledged by security operator.
2. **Investigate**: Shows full contributing signal weights, file list, and process telemetry.
3. **Contain / Suspend**: Terminates or suspends malicious process handle.
4. **Safe Rollback**: Restores original files from quarantine / backup shadows.

---

## 3. Mobile Dashboard Specification (`dashboard.py`)

The companion dashboard is responsive, cyber-dark, and accessible via mobile browsers (`http://<ip>:8765/dashboard` or over Cloud Relay):

- **Device Status & Metrics**: Laptop name, online state, live CPU %, RAM %, disk %, and battery status.
- **Windows & Tabs**: Active foreground application, current browser domain, start time, and live duration counter.
- **Downloads Interceptor**: File name, size, origin domain, timestamp, and security verdict badge.
- **File Activity Log**: Searchable, filterable list of created, modified, moved, and deleted files with responsible processes.
- **Security & Alerts**: Total threat counter, severity breakdown bar, and interactive **Simulate Ransomware Alert** test button.
- **Scope & Privacy**: Displays authorized directories, privacy guarantees, and token rotation controls.

---

## 4. Verification & Testing Results

The comprehensive test suite verifies all functional modules and edge cases:
- `agent/tests/test_comms_bridges.py`: Cloud relay token derivation, HMAC validation, offline buffering.
- `agent/tests/test_window_and_download_monitors.py`: Privacy redaction, duration tracking, download YARA/entropy scan.
- `agent/tests/test_file_monitor.py`: Folder creation, burst detection, mass encryption detection.
- `agent/tests/test_local_server.py`: REST routes, scope updates, alert simulation, response actions.
- `agent/tests/test_risk_scoring.py`: 5-tier scoring, contributing signal explainability.
- `agent/tests/test_tamper_protection.py`: Agent process integrity, configuration protection.

**Test Run Result**: `103 passed, 1 warning in 25.59s` (100% pass rate).

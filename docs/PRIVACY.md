# Privacy Design — AI-Powered Personal Security Layer

---

## Privacy Philosophy

This project follows **privacy-by-design** principles. Security monitoring inherently requires observing system behavior, but observation must be limited to what is strictly necessary for the security function. The system is designed to protect the user, not surveil them.

> **Core principle:** The system monitors *what* is running, *where* it connects, and *how* files change — not *what* the user is doing, reading, writing, or communicating.

---

## 1. What Information Is Collected

The agent collects **system-level metadata** about processes, file system events, network connections, and startup changes. It does not collect personal content.

### Collected (System Metadata)

| Category | What is collected | Purpose |
|---|---|---|
| Process metadata | Process name, PID, parent PID, executable path, username running the process, start time | Detect suspicious process behavior |
| Process command-line arguments | Arguments to known scripting hosts (PowerShell, cmd.exe, etc.) | Detect malicious script execution patterns |
| File event metadata | File path, event type (create/modify/delete/rename), file extension, SHA-256 hash (executables only) | Detect malware file drops, ransomware-like modifications |
| Network connection metadata | Local port, remote IP, remote port, protocol, owning PID | Detect suspicious network communication |
| Startup/persistence entries | Registry key name, target path (no values beyond path) | Detect malware persistence mechanisms |
| Risk scores | Computed risk score over time | Security posture monitoring |
| Agent operational logs | Agent startup, errors, sync events | Agent health and debugging |

### NOT Collected

| Category | Explicit exclusion |
|---|---|
| **File content** | The content of user documents, source code, emails, databases, or any other files is NEVER read, transmitted, or stored |
| **Keystrokes** | No keyboard input is captured |
| **Screenshots** | No screen capture of any kind |
| **Clipboard content** | No clipboard monitoring |
| **Browser history or cookies** | No web activity monitoring |
| **Email content** | No email access |
| **Chat messages** | No messaging application access |
| **Microphone or camera** | Not accessed |
| **Contacts, photos, or location** | Mobile app does not request these permissions |
| **Network packet content** | Packet payload content is not captured; only connection metadata (IP, port, PID) |
| **User-visible document content** | Full command-line arguments of scripting hosts are captured for analysis, but actual document content accessed by those processes is not |

---

## 2. Why It Is Collected

Each data point collected has a documented security purpose:

| Data | Why collected |
|---|---|
| Process name + parent PID | To detect suspicious parent-child process relationships (e.g., Word spawning PowerShell) |
| Executable path | To identify processes running from unusual locations (e.g., Temp directory) |
| Command-line arguments (scripting hosts) | To detect encoded commands, download cradles, and execution policy bypasses |
| File event metadata | To detect mass file modification (ransomware indicator), executable drops |
| File SHA-256 hash (executables) | To detect known malicious files by hash |
| Network connection metadata | To detect suspicious outbound connections from unusual processes |
| Startup registry entries | To detect malware persistence |
| Risk score | To provide the user with a security posture indicator |

---

## 3. Data Minimization

Data minimization is applied at every stage:

| Stage | Minimization applied |
|---|---|
| Telemetry collection | Only security-relevant fields collected; CPU%/memory% collected in aggregate, not per-user-activity |
| Feature extraction | Raw command-line arguments are processed into boolean features (has_encoded_args: true/false); the raw argument string is not stored in the backend database |
| Backend storage | `features` JSONB field contains derived attributes only, not raw strings |
| Push notifications | FCM payload contains only alert ID and severity — no sensitive telemetry |
| Mobile app display | Alert descriptions are written in plain language; raw feature data is optional in event detail screen |

---

## 4. Local Processing

The following processing occurs entirely on the laptop and is never transmitted to the backend:

- Raw telemetry collection.
- Feature extraction and normalization.
- Rule-based detection.
- AI anomaly scoring.
- Risk score computation.
- All detection logic.

Only **results** (structured events, alerts, risk scores) are transmitted — not raw telemetry.

---

## 5. Cloud Processing

The backend receives and stores:

- Structured security events (derived features, not raw data).
- Alerts (descriptions, severity, rule IDs, anomaly scores).
- Risk score history.
- Heartbeat signals (device online status).

The backend does NOT:

- Re-analyze raw telemetry.
- Store command-line arguments in plaintext.
- Store file contents.

The AI model is local-only in the MVP. No feature vectors are sent to an external AI/ML service.

---

## 6. Third-Party Data Sharing

| Third Party | What is shared | Purpose | Privacy consideration |
|---|---|---|---|
| Firebase Cloud Messaging (FCM) | Alert ID, severity level, device FCM token | Push notification delivery | FCM is a Google service; Google processes the notification payload. Payload is kept minimal (no raw telemetry). |
| Cloud hosting provider (backend) | All backend data (encrypted in transit, stored at rest on provider infrastructure) | Hosting | Standard cloud hosting trust model; provider has physical access to server storage |

No security event data is shared with any threat intelligence service in the MVP.

---

## 7. User Consent

Before the agent is installed and begins monitoring, the user must be informed of:

- What telemetry is collected.
- What is explicitly NOT collected.
- Where data is stored (locally and on the backend).
- How long data is retained.
- How to delete their data.

This information should be presented clearly during agent setup (installer or first-run prompt).

---

## 8. Data Retention

| Data | Local (SQLite) | Backend (PostgreSQL) |
|---|---|---|
| Security events | 30 days; older events purged | 30 days; configurable |
| Alerts | 30 days | 90 days |
| Risk score history | 30 days | 30 days full; summarized to hourly averages for 30–90 days |
| Response actions | 30 days | 90 days |
| Offline queue | Cleared on successful sync | N/A |

Retention periods are conservative minimums for the MVP. Shorter retention is privacy-better. Future versions should allow user-configurable retention periods.

---

## 9. Data Deletion

| Scenario | What happens |
|---|---|
| User deletes account | All user data, device records, events, alerts, and risk scores in the backend must be deleted |
| User deregisters a device | Device record, events, alerts, and scores for that device are deleted from the backend |
| User clears the agent | Local SQLite database is deleted; device token is revoked on the backend |
| Automatic retention expiry | Events and alerts older than the retention period are automatically purged |

Data deletion on account removal must be complete — no orphaned records remain.

---

## 10. Mobile Notification Privacy

Push notifications carry minimal data:

```json
{
  "title": "High Severity Alert",
  "body": "Suspicious activity detected on Work Laptop",
  "data": {
    "alert_id": "alt_20260916_001",
    "severity": "HIGH"
  }
}
```

Notifications do NOT contain:

- Process names or executable paths.
- File paths or hashes.
- IP addresses.
- Command-line arguments.
- Any personal file information.

The mobile app fetches full alert details from the backend only when the user taps the notification. This fetch is authenticated and occurs over HTTPS.

---

## 11. Privacy Risks

| Risk | Description | Mitigation |
|---|---|---|
| Sensitive paths in file events | File paths may reveal user directory structures (e.g., `C:\Users\Alice\private\`) | Only metadata (path prefix and file extension) used for detection; specific filenames in sensitive directories are not transmitted in full |
| Process names revealing software use | Process list reveals what software the user runs | Process names are security-necessary; minimized in transmission |
| Command-line arguments | May contain sensitive parameters (e.g., file paths in script arguments) | Raw arguments are not stored in the backend; only derived boolean features are transmitted |
| Network metadata revealing services | Remote IPs reveal what services a process connects to | This is necessary for network-based detection; IPs are not shared externally |
| Risk of insider threat at backend | Someone with backend database access could see security event history | Access control to the backend database; encryption at rest in production |

---

## 12. Recommended Safeguards

1. **Full-disk encryption** on the laptop: Protects local SQLite if the laptop is stolen.
2. **Encrypted database at rest** on the backend: Protects the PostgreSQL database if the server is compromised.
3. **Minimal FCM payload**: Already implemented (alert ID + severity only).
4. **Process exclusion lists with care**: Exclusions can be abused. Keep exclusion lists minimal and path-based.
5. **Regular data deletion**: Implement automatic purge of data beyond the retention window.
6. **User transparency**: Provide a way for users to see what data is stored about them.
7. **No external AI APIs**: Do not send feature vectors to external AI services without explicit user consent and a clear privacy review.

---

*Document version: 1.0 | Last updated: 2026-09-16*

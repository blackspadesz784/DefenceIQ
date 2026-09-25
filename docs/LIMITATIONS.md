# Limitations — AI-Powered Personal Security Layer

---

## Important Preamble

This document is a factual, honest account of the system's limitations. These are not failure points to be fixed before launch — many are inherent to the approach. Understanding these limitations is essential for using the system correctly and for setting appropriate expectations.

> **This system is a personal security layer — an additional monitoring and alerting tool. It is not a commercial antivirus, not an enterprise EDR solution, and not a guaranteed malware detector.**

---

## 1. False Positives

### What they are
A false positive is an alert triggered by legitimate, benign system behavior that was mistakenly classified as suspicious.

### Why they occur in this system
- Behavioral rules are necessarily broad to catch novel attacks — this means legitimate software can trigger them.
- The AI anomaly model flags anything that deviates from its training baseline, including legitimate but unusual user activity.
- A developer running an unusual build script, a backup tool modifying many files, or an update process adding a Registry entry can all trigger rules.

### Specific known false positive sources

| Legitimate Action | Rule It May Trigger |
|---|---|
| Cloud storage sync (OneDrive, Dropbox) syncing thousands of files | Mass file modification rule |
| Compiler or build system creating many processes | Process creation rate rule |
| Remote management tools modifying the Registry | Persistence detection rule |
| IT management or antivirus software | Process monitoring, file access rules |
| Password manager accessing the Registry | Persistence / Registry monitoring |
| Developer running PowerShell build scripts | Script execution rules |
| Installer running from Downloads | Executable-in-temp rule |
| Security research tools | Many rules simultaneously |

### Mitigation
- Multi-signal correlation reduces false positives by requiring multiple suspicious signals before generating an alert.
- User-configurable exclusion paths can suppress known-safe paths.
- Score decay means brief spikes from legitimate behavior do not persist.

### User responsibility
**Users must review alerts with context before taking any action.** An alert is a signal for investigation, not a confirmed threat verdict.

---

## 2. False Negatives

### What they are
A false negative is a real threat that the system fails to detect.

### Why they occur in this system

**Rule-based detection misses:**
- Novel attack techniques not covered by the current ruleset.
- Attacks that use legitimate, signed system tools in ways that are hard to distinguish from legitimate use.
- Slow, patient attacks that operate below behavioral thresholds.
- Fileless attacks that execute entirely in memory without touching the file system.

**AI anomaly detection misses:**
- Attacks specifically crafted to blend with the system's baseline (adversarial evasion).
- An AI model trained only on benign data cannot reliably classify specific malware categories.
- The MVP Isolation Forest does not model time sequences — it cannot detect patterns that only emerge over hours or days.

### Known undetectable scenarios

| Scenario | Why not detectable |
|---|---|
| Kernel rootkit | Agent operates in userspace; kernel-level threats are below its visibility |
| Firmware/BIOS attack | Far below the monitoring layer |
| Attacker who disables the agent first | Once the agent is stopped, monitoring stops |
| Malware that mimics a legitimate, signed system binary behavior | Path and signature checks pass |
| Encrypted C2 traffic on port 443 blending with HTTPS | Cannot distinguish malicious HTTPS from legitimate HTTPS at metadata level |
| Slow, gradual data exfiltration below rate thresholds | Behavioral rate limits not triggered |
| Memory-only (fileless) malware | No file events generated |

---

## 3. Operating System Differences

### MVP limitation: Windows only

The MVP targets Windows 10 and Windows 11. All monitoring APIs (`winreg`, `pywin32`, Windows WMI, `watchdog` Windows backend) are Windows-specific.

- **macOS:** Different monitoring APIs (kqueue, FSEvents, macOS-specific authorization); separate implementation required.
- **Linux:** Different APIs (inotify, /proc filesystem); separate implementation required.
- A future cross-platform agent would need platform-specific implementations behind a common interface.

### Windows version differences

| Feature | Windows 10 | Windows 11 |
|---|---|---|
| WMI process creation events | Supported | Supported |
| Windows Registry monitoring | Supported | Supported |
| `psutil` features | Fully supported | Fully supported |
| Startup folder location | Standard | Standard |

No known Windows version incompatibilities for MVP features. Older Windows 10 versions (pre-1903) have not been tested.

---

## 4. Permission Restrictions

### What the agent can access without elevation

The agent intentionally runs without elevated privileges (non-administrator) for the MVP. This limits what it can monitor:

| Access | Available without admin |
|---|---|
| Own process list | ✅ (via psutil) |
| Most process metadata | ✅ |
| Process command-line arguments of other user's processes | ⚠️ May require elevation on some Windows configurations |
| File system events in user directories | ✅ |
| File system events in system directories (C:\Windows\System32) | ⚠️ Observation only; some operations require admin |
| Registry Run keys (HKCU) | ✅ |
| Registry Run keys (HKLM) | ✅ (read only) |
| Network connection table | ✅ |

### What is NOT accessible without elevation

- Kernel-level events.
- Other users' processes on a shared system.
- Processes running as SYSTEM.
- Windows kernel objects.

Some monitoring capabilities may be reduced on hardened systems with restrictive security policies.

---

## 5. AI and ML Limitations

### No guaranteed detection capability

The Isolation Forest anomaly model does not detect specific malware. It detects behavioral deviations from a training baseline. A sophisticated threat that stays within normal behavioral parameters will not be detected.

### Training data limitations

- The MVP model is trained only on benign behavior samples from a limited number of system configurations.
- The model's accuracy degrades on systems with significantly different software profiles from the training environment.
- A developer's machine with frequent PowerShell and compiler usage will have a different baseline than an office worker's machine — a model trained on one may have high false positives on the other.

### No model retraining in MVP

The MVP ships a static trained model. As the user installs new software, updates the OS, or changes usage patterns, the model's baseline becomes stale. This is expected to increase false positive rates over time.

### Adversarial evasion

Anomaly detection can be evaded by an attacker who understands the model's training data and deliberately keeps their behavior within the learned normal range. This is a known limitation of anomaly-based detection and is not unique to this system.

---

## 6. Offline Limitations

When the laptop has no internet access:

- **All core security monitoring continues.** This is by design.
- Security events are queued locally. The queue has a maximum size (configurable; default 10,000 events). If the queue exceeds this limit, the oldest events are rotated out. Extended offline periods with very high event rates may result in lost older events.
- **The mobile dashboard cannot be updated during offline periods.** The mobile app displays the last-known status.
- **Push notifications are not delivered** during offline periods. They are not queued by FCM indefinitely — notifications older than FCM's delivery window may be dropped.
- **After a very long offline period**, the risk score history visible in the mobile dashboard will show a gap.

---

## 7. Network Dependency

While core monitoring is offline-capable, the following features require internet connectivity:

| Feature | Requires internet |
|---|---|
| Event transmission to backend | ✅ |
| Mobile dashboard (real-time) | ✅ |
| Push notifications | ✅ |
| Device heartbeat / online status | ✅ |
| Rule updates from backend (Phase 2) | ✅ |
| Threat intelligence lookup (Phase 2) | ✅ |
| Cloud AI inference (future) | ✅ |

---

## 8. Resource Consumption

The agent is designed to be lightweight, but security monitoring has inherent resource costs:

| Condition | Expected resource use |
|---|---|
| Agent idle (no events) | < 2% CPU, < 100 MB RAM |
| Active detection (many events) | Up to 10% CPU peak |
| AI inference running | Brief CPU spike, < 100 ms |
| File monitor during large file sync | Elevated CPU due to event volume from watchdog |

On older or lower-specification hardware (e.g., a laptop with a dual-core CPU and 4 GB RAM), the agent's resource footprint may be more noticeable.

**Mitigation:** Monitored directories can be scoped in the config to exclude high-traffic directories (e.g., cloud sync folders) to reduce watchdog load.

---

## 9. Detection Evasion

Sophisticated attackers with knowledge of this system can attempt to evade detection:

| Evasion technique | Effect on this system |
|---|---|
| Using signed, legitimate system tools (LotL) | Rules partially detect this; complete detection is not guaranteed |
| Operating slowly, below rate thresholds | Behavioral rate rules not triggered |
| Renaming malware to match a trusted process name | Partially mitigated by path legitimacy; not fully mitigated |
| Disabling the agent directly | Eliminates all monitoring |
| Modifying detection rules (if file access available) | Rule-based detection degraded |
| Operating entirely in memory | File and process file-based features not triggered |

This system provides meaningful defense-in-depth, but it is not evasion-proof.

---

## 10. Automated Response Risks

When automated response actions are implemented (Phase 2+), they carry specific risks:

| Risk | Description |
|---|---|
| False positive → process killed | A legitimate process could be terminated, disrupting user work or data |
| False positive → file quarantined | A legitimate file could be made inaccessible, potentially breaking an application |
| Response action exploited | An attacker who can send crafted events could attempt to trigger false responses against legitimate processes |
| Cascading termination | Killing one process could cause others that depend on it to fail |

**This is why the MVP does NOT implement automated process termination or file quarantine.** All automated actions in the MVP are limited to logging and flagging. Destructive actions require explicit user confirmation (Phase 2).

---

## 11. Privacy Limitations

- Process command-line arguments for scripting hosts are inspected. These may include paths or parameters that indirectly reveal user activity (e.g., the path to a file being processed by a script).
- The list of running processes reveals what software the user is running.
- Network connection metadata reveals which IP addresses the user's processes connect to.

These are necessary for the security function and are explicitly documented in [PRIVACY.md](PRIVACY.md). Users who require stronger privacy guarantees should review the privacy document and consider configuring narrow monitoring scope.

---

## 12. Prototype Limitations

This is a research prototype, not a production security product:

| Prototype Limitation | Description |
|---|---|
| Not continuously updated | Detection rules and AI model are not automatically updated with new threat intelligence |
| Limited ruleset | The initial ruleset covers a curated set of patterns; new threat techniques are not automatically added |
| No certification | Not evaluated against any security certification standard (Common Criteria, FIPS, etc.) |
| No SLA | No uptime or detection rate guarantees |
| No support model | No security incident response or vendor support |
| Not a replacement | Does not replace commercial antivirus, EDR, or professional security monitoring |

---

*Document version: 1.0 | Last updated: 2026-09-16*

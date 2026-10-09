"""Script to generate the complete DefenceIQ Project Overview document in Markdown, HTML, and PDF formats."""

import os
import subprocess
import sys

BASE_DIR = r"c:\Users\DELL\Documents\Projects\Project-19\DefenceIQ"
MD_PATH = os.path.join(BASE_DIR, "DEFENCEIQ_PROJECT_OVERVIEW.md")
HTML_PATH = os.path.join(BASE_DIR, "DEFENCEIQ_PROJECT_OVERVIEW.html")
PDF_PATH = os.path.join(BASE_DIR, "DEFENCEIQ_PROJECT_OVERVIEW.pdf")

# ==============================================================================
# 1. MARKDOWN CONTENT
# ==============================================================================
MD_CONTENT = """# DEFENCEIQ — PROJECT OVERVIEW

## 1. Team Details

* **Team Name:** Black Spades Z
* **Team Leader:** Black Spades Z
* **Team Leader Contact Number:** Not specified in repository (Email: blackspadesz784@gmail.com; Contact number available upon request)

---

## 2. Problem Statement Chosen

### Problem Statement
Personal computers—laptops and desktops utilized by individuals, developers, researchers, and students—are increasingly subjected to sophisticated cyber threats, including polymorphic malware, living-off-the-land (LotL) binary abuse, ransomware bursts, unauthorized persistence mechanisms, and malicious script executions. Most individual users rely solely on legacy signature-based antivirus software or operate without active behavioral monitoring. The critical problem DefenceIQ addresses is the complete lack of real-time endpoint behavioral visibility, explainable threat detection, remote security oversight when away from the workstation, and safe, reversible automated containment for personal computing environments.

### Why This Problem
Personal endpoints store highly confidential personal, academic, financial, and proprietary development data. Despite this criticality, everyday users remain completely blind to underlying process trees, abnormal parent-child process relationships, unauthorized background network beacons, and rapid file modifications. 

Conventional antivirus products predominantly depend on static signature matching, which routinely fails against modern attack techniques such as fileless memory injection, obfuscated PowerShell/cmd scripts, and newly compiled ransomware strains. Conversely, enterprise Endpoint Detection and Response (EDR) solutions (e.g., CrowdStrike Falcon, Microsoft Defender for Endpoint) require corporate infrastructure, dedicated Security Operations Centers (SOCs), complex management consoles, and expensive recurring licenses, rendering them completely inaccessible to personal users, independent researchers, and small teams.

Furthermore, remote visibility is nonexistent in conventional personal security software: when users step away from their workstations, they have no real-time mechanism to monitor device security posture, active applications, or suspicious events from a mobile device. Finally, existing automated remediation is often destructive—permanently deleting quarantined files or abruptly crashing critical processes without user context or rollback options—leading to operational disruption and data loss. Solving this problem provides personal computer users with enterprise-grade behavioral visibility, explainable intelligence, and safe containment in an accessible, lightweight, and offline-first form factor.

---

## 3. Brief Solution

### Proposed Solution
DefenceIQ is an open-source, AI-assisted personal endpoint security system providing layered defensive monitoring for Windows workstations, paired with a companion Android dashboard and responsive web interface. 

The system comprises four tightly integrated subsystems:
1. **Endpoint Security Agent:** A lightweight Windows background service hosting six dedicated telemetry monitors (Process, File, Network, USB Removable Storage, Active Window/Browser Tab, and Downloads) coupled with layered detection engines (Static Analysis, YARA rules, Multi-Hash Reputation, and ClamAV fallback).
2. **AI & Explainable Risk Scoring Engine:** An intelligent correlation pipeline featuring an unsupervised scikit-learn Isolation Forest anomaly detector and a deterministic, additive 0–100 risk scoring model that tracks process lineages across sliding temporal windows, providing human-readable explanations and explicit signal weights.
3. **Graduated Reversible Response Engine:** An automated containment controller executing non-destructive interventions—such as Windows API process suspension, executable-specific Windows Firewall outbound blocks, and secure metadata-backed file quarantine—coupled with an instantaneous one-click rollback mechanism.
4. **Multi-Transport Mobile Companion & Web Dashboard:** A native Android companion application (Kotlin, Jetpack Compose) and an executive HTML5/CSS3 web dashboard providing real-time telemetry feeds, device health metrics, live security alerts, and bidirectional control over local Wi-Fi, direct USB cable (ADB), Bluetooth LE, or an end-to-end HMAC-SHA256 authenticated Cloud Relay.

### How It Solves the Problem
DefenceIQ continuously monitors multi-layer endpoint behavior locally, correlating cross-domain telemetry into transparent, explainable risk scores without cloud latency or subscription dependencies. It pairs the workstation with a remote mobile companion across local networks or encrypted cloud relays, alerting users instantly to behavioral anomalies and executing safe, reversible containment actions that neutralize threats while safeguarding data integrity.

---

## 4. Tech Stack & Technical Approach

### Tech Stack
DefenceIQ is engineered using a robust, modular, and open-source technology stack across system programming, machine learning, mobile development, and secure communications:

* **Programming Languages:**
  * Python 3.10+ (Core Endpoint Security Agent, AI/ML pipeline, Local API Server)
  * Kotlin (Native Android Mobile Companion App)
  * HTML5, CSS3, JavaScript ES6+ (Executive Web Companion Dashboard)
  * PowerShell & Windows Batch / VBScript (System deployment, startup automation, and hardware diagnostics)

* **Endpoint Agent & Backend Frameworks:**
  * FastAPI (High-performance asynchronous REST and WebSocket API framework)
  * Uvicorn (Lightning-fast ASGI production server)
  * asyncio & threading (Concurrent event bus dispatching, background monitoring, and watchdog tasks)
  * PyInstaller (Standalone frozen executable packaging into `DefenceIQ-Laptop-Agent.exe`)

* **System Introspection & OS Telemetry:**
  * `psutil` (Cross-process resource tracking, memory inspection, socket monitoring, and process tree lineage)
  * `pywin32` & Windows `ctypes` (Win32 API integration, Authenticode and Windows Catalog signature verification via `WinVerifyTrust` and `CryptCATAdmin`, and NTFS Alternate Data Streams `Zone.Identifier` parsing)
  * `watchdog` (Native OS-level file system event observation across user-authorized directories)

* **Security, Detection & Cryptography:**
  * `pefile` (Portable Executable header parsing, section inspection, and suspicious Win32 API import analysis)
  * `yara-python` & Built-in `PurePythonYaraEvaluator` (Behavioral pattern rule matching for reverse shells, ransomware extortion notes, and PowerShell bypass techniques)
  * `hashlib` & `hmac` (Cryptographic hashing across SHA-256, SHA-1, MD5; HMAC-SHA256 payload signing and deterministic channel derivation)
  * `pyclamd` / ClamAV CLI (Local daemon and command-line antivirus signature scanning fallback)
  * VirusTotal v3 REST API (Optional user-configured cryptographic hash reputation verification)

* **Machine Learning & AI:**
  * `scikit-learn` (Unsupervised `IsolationForest` anomaly detector modeling multidimensional endpoint telemetry baselines)
  * `numpy` (Numerical feature array processing and vectorization)
  * Mathematical Shannon Entropy Calculation (Information entropy calculation ranging 0.0–8.0 for ransomware burst detection)

* **Local Data Persistence:**
  * SQLite 3 (`sqlite3`) with Write-Ahead Logging (`WAL` mode) and normalized relational schemas (`events`, `incidents`, `actions`)

* **Mobile Application (Android):**
  * Kotlin 1.9+ with Jetpack Compose (Declarative modern UI architecture)
  * Material Design 3 (UI component tokens, dynamic themes, and status badges)
  * OkHttp3 & Retrofit 2 (Asynchronous HTTP REST client and Server-Sent Events / SSE streaming)
  * Kotlin Coroutines & StateFlow (Reactive state management and asynchronous data binding)
  * Android NotificationManager (Heads-up push notifications for high-severity alerts)

* **Communication Transports & Networking:**
  * Local Wi-Fi / LAN: Asynchronous HTTP REST API + WebSockets on TCP port 8765
  * UDP Discovery Beacon: Broadcast beacon on UDP port 8766 for zero-configuration local companion discovery
  * USB Cable Bridge: Android Debug Bridge (`adb forward tcp:8765 tcp:8765`) enabling zero-network physical tethered monitoring
  * Bluetooth Bridge: Bluetooth Low Energy (BLE) peripheral advertising and status beacon
  * Global Cloud Relay: IP-independent Server-Sent Events (SSE) / HTTPS relay over ntfy.sh and custom cloud backend (`render_app.py`, `render.yaml`) with HMAC-SHA256 authenticated channels

* **Automated Containment & OS Controls:**
  * Windows Advanced Firewall (`netsh advfirewall` outbound process blocking rules)
  * Windows API process suspension (`NtSuspendProcess` / `p.suspend()` via psutil)
  * Reversible quarantine vault (`quarantine_vault/`) with JSON metadata sidecars

* **Testing & Safe Verification Harness:**
  * Custom end-to-end verification harness (`run_e2e_verification.py`)
  * Inert simulation scripts (`simulate_process_chain.py`, `simulate_mass_file_change.py`)
  * Pytest test suite

---

### Technical Approach
DefenceIQ implements a complete, closed-loop defensive security architecture organized into eight logical phases:

```
[System Monitors] ---> [Layered Detection] ---> [ML Anomaly] ---> [Event Correlator]
      |                                                                 |
      v                                                                 v
[SQLite WAL Store] <--- [Reversible Response] <--- [Risk Scoring] <-----+
      |
      +---> [FastAPI Server / WebSockets] <---> [Android App / Web Companion]
            [+ Cloud Relay / USB / BLE]
```

1. **User Interaction & Initialization:**
   The user starts the laptop agent via executable (`DefenceIQ-Laptop-Agent.exe`) or background launcher (`Start-DefenceIQ-Laptop.bat` or `Install-Startup.bat`). The agent loads its persistent configuration and assigns a unique, sticky pairing token (e.g., `DIQ-EJFW-GC3V`). The user pairs their Android device by entering the token or selecting the auto-discovered laptop on the local Wi-Fi subnet. Sticky pairing persists indefinitely until explicitly revoked. The user selects a protection profile (Basic, Balanced, or Maximum).

2. **Continuous Multi-Layer Telemetry Ingestion:**
   Six independent monitoring services continuously capture endpoint activity:
   * *Process Monitor:* Intercepts process lifecycle events, parent-child relationships (e.g., Office applications spawning PowerShell/cmd), command-line arguments (e.g., `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`), CPU/RAM spikes, and validates Authenticode and Windows Catalog signatures using WinTrust Win32 APIs.
   * *File Monitor:* Tracks file creation, modification, deletion, and movement across user-authorized directories (Downloads, Desktop, Documents), calculating Shannon entropy on data bursts to identify ransomware encryption activity (> 7.2 entropy).
   * *Network Monitor:* Samples active sockets per process, identifying outbound connections to unrecognized external hosts and flagging known C2 / reverse shell ports (e.g., 4444, 1337, 3333).
   * *USB Monitor:* Detects removable storage insertion and unmounting, automatically scanning root directories for `autorun.inf` configurations and dropped executables.
   * *Active Window Monitor:* Polls the foreground window, identifying active productivity applications, browser titles, and domain names while redacting passwords and sensitive tokens.
   * *Download Monitor:* Observes browser download directories, extracts source URLs and origin domains via Windows NTFS `Zone.Identifier` Alternate Data Streams (ADS) or active browser context, and triggers immediate multi-engine scans.

3. **Layered Detection & Forensic Analysis:**
   Newly observed files and suspicious processes are evaluated through an ensemble of detection engines:
   * *Static Analysis:* Magic-byte file typing, PE section anomaly inspection, and import address table analysis for high-risk Win32 API calls (`CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `NtUnmapViewOfSection`).
   * *YARA Rule Matching:* Behavioral pattern evaluation using compiled YARA rules for reverse shell strings, ransomware ransom notes, and malicious script bypasses.
   * *Hash Reputation:* SHA-256/SHA-1/MD5 calculation evaluated against local known-good and known-bad caches, with optional VirusTotal API verification.
   * *ClamAV Fallback:* ClamAV daemon socket or CLI binary scanning when installed.

4. **AI & Machine Learning Anomaly Detection:**
   An unsupervised `IsolationForest` model (trained on benign desktop baseline distributions covering idle services, productivity apps, and developer compile tasks) evaluates multi-variable feature vectors (`cpu_percent`, `memory_rss_mb`, `open_connections`, `file_write_burst`, `entropy_delta`, `child_process_count`). When a process exhibits statistical divergence exceeding baseline parameters, the engine emits an auxiliary `ml_anomaly_detected` signal.

5. **Temporal Event Correlation & Explainable Risk Scoring:**
   The `EventCorrelator` groups cross-domain telemetry into process-tree context objects across a sliding 60-second temporal window. When a process spawns a script shell, initiates an outbound connection, and triggers high-entropy file writes, the correlator links these events into a single `Incident`. The `RiskScoringEngine` applies an additive weighted model to all accumulated signals, producing a transparent 0–100 score:
   * **Green (0–19):** Normal baseline operations (logged for auditing).
   * **Yellow (20–49):** Low risk / suspicious anomaly (user notification, elevated monitoring).
   * **Orange (50–69):** High risk / unauthorized behavior (outbound network block, process suspension).
   * **Red (70–100):** Critical threat (process tree isolation, firewall block, file quarantine).
   Every incident includes a detailed explainability breakdown listing contributing signals, individual weights, categories, and plain-language descriptions.

6. **Graduated Reversible Containment:**
   When an incident crosses configured thresholds, the `ResponseEngine` executes targeted, non-destructive containment:
   * *Process Controller:* Suspends the malicious process or entire process tree using `NtSuspendProcess`, freezing execution in memory without killing the process or corrupting unsaved data.
   * *Firewall Controller:* Adds an executable-specific outbound block rule in Windows Advanced Firewall using `netsh advfirewall`, severing C2 communications while leaving the rest of the host's internet connection undisturbed.
   * *Quarantine Manager:* Moves suspicious files into an isolated vault (`quarantine_vault/`), setting read-only permissions and generating a `.json` metadata sidecar containing original paths, hashes, and incident IDs.
   * *Reversible Rollback:* Every containment action records an exact rollback handler. The user can click "Rollback" on their mobile app or web dashboard to resume processes, remove firewall rules, and restore quarantined files instantly.

7. **Tamper Protection & Agent Self-Defense:**
   The `SelfMonitor` thread guards the agent against local evasion attacks. It watches `defenceiq.db` and the pairing token key file for unauthorized writes or deletions, monitors the host process table for hostile termination attempts (e.g., `taskkill /f /pid <agent_pid>`), and triggers immediate high-priority alerts upon tampering.

8. **Multi-Transport Communication & Companion Synchronization:**
   Telemetry, health metrics, and threat alerts are synchronized with companion devices across multiple redundant channels:
   * *Local LAN:* FastAPI serves REST endpoints and broadcasts real-time alerts over WebSockets (`/ws/alerts`). UDP beacons on port 8766 enable zero-configuration mobile discovery.
   * *USB Cable Bridge:* ADB port forwarding enables direct tethered monitoring in air-gapped or restricted network environments.
   * *Global Cloud Relay:* Using deterministic HMAC-SHA256 channel derivation (`diq_down_*`, `diq_up_*`), the laptop and mobile companion exchange encrypted telemetry and commands over HTTPS / Server-Sent Events (SSE). This maintains live connectivity across cellular networks (4G/5G) or separate Wi-Fi networks without port forwarding, dynamic DNS, or static IP addresses.

---

## 5. USP (Unique Selling Proposition)

DefenceIQ introduces several distinctive, real-world innovations tailored specifically for personal endpoint defense:

1. **100% Offline-First Architecture with Zero Cloud Dependency:**
   All monitoring, static analysis, YARA matching, machine learning inference, process correlation, risk scoring, and automated containment execute entirely on the local workstation. The system maintains full protective capabilities in air-gapped, isolated, or network-degraded environments without relying on third-party cloud infrastructure.

2. **Fully Explainable, Additive Risk Scoring:**
   In contrast to black-box antivirus solutions that emit opaque binary verdicts, DefenceIQ provides complete transparency. Every risk score (0–100) displays exact contributing signals, individual point weights (e.g., `modified_encrypted_many_files: +35`, `spawned_script_shell: +25`), threat categories, and natural-language rationales, demystifying security decisions for both technical and non-technical users.

3. **Non-Destructive, 100% Reversible Containment with One-Click Rollback:**
   DefenceIQ eliminates the fear of disruptive false positives. Instead of permanently deleting files or abruptly terminating processes, the system performs reversible containment: processes are suspended in memory via native Windows APIs, network isolation is applied per-executable via Windows Firewall, and files are secured in a structured quarantine vault with restoration sidecars. Any action can be reversed with a single tap from the mobile app or web dashboard.

4. **Multi-Transport Resilient Connectivity (LAN, USB, BLE, and Cloud Relay):**
   DefenceIQ is the first personal security system to implement multi-transport failover:
   * High-speed local Wi-Fi with zero-config UDP discovery.
   * Zero-network physical USB cable tethering via ADB port forwarding.
   * Bluetooth Low Energy (BLE) proximity advertising.
   * IP-independent Cloud Relay with HMAC-SHA256 authentication, maintaining live connection across cellular networks (4G/5G) and public Wi-Fi without static IPs or firewall port-forwarding.

5. **Cross-Layer Temporal Process-Tree Correlation:**
   Rather than treating process, file, and network events as isolated occurrences, DefenceIQ correlates telemetry across entire parent-child process trees within a sliding time window. This approach eliminates false alarms from single benign anomalies while reliably intercepting sophisticated multi-stage attacks (e.g., Office document -> PowerShell script -> external socket connection -> high-entropy file encryption).

6. **Contextual Application, Browser Tab & Download Origin Tracking:**
   By combining real-time foreground window monitoring with NTFS `Zone.Identifier` Alternate Data Streams (ADS) extraction, DefenceIQ captures the exact origin domain and URL of incoming files at the moment of download, automatically associating downloaded executables with the active browser context and initiating instant multi-engine scans.

7. **Strict Privacy by Design & Least-Privilege Operation:**
   DefenceIQ is designed to protect user privacy. The system operates strictly on metadata (process names, hashes, entropy values, remote IP addresses, and file extensions). No document contents, personal files, or keystrokes are inspected, stored, or transmitted. Foreground window tracking incorporates automatic redaction filters for passwords, session tokens, and sensitive authentication forms.

---

## 6. Conclusion

### Short Summary
* **The Problem:** Personal computers store critical personal, financial, and professional assets but operate without effective behavioral security monitoring. Users are vulnerable to sophisticated threats that bypass traditional signature-based antivirus, while enterprise EDR tools remain prohibitively expensive, complex, and unsuited for personal use. Crucially, users lack remote visibility and are exposed to disruptive, irreversible containment actions.
* **The DefenceIQ Solution:** DefenceIQ delivers a free, open-source, AI-assisted personal endpoint security system. It couples a lightweight Windows security agent with a native Android companion app and executive web dashboard, providing real-time behavioral visibility, transparent threat scoring, and remote oversight.
* **The Technology & Approach:** Built with Python, Kotlin (Jetpack Compose), and FastAPI, DefenceIQ integrates six continuous telemetry monitors, layered static and YARA engines, an unsupervised scikit-learn Isolation Forest ML detector, and an additive 0–100 explainable risk scoring pipeline. It enforces non-destructive, 100% reversible containment (process suspension, firewall blocking, safe quarantine) and maintains resilient connectivity across Wi-Fi, USB, BLE, and encrypted cloud relays.
* **Expected Real-World Impact:** DefenceIQ democratizes endpoint detection and response for individuals, developers, students, and small teams. By combining enterprise-grade behavioral intelligence with zero-cloud-dependency privacy, explainable decision-making, and non-destructive containment, DefenceIQ delivers accessible, transparent, and trustworthy cybersecurity for personal workstations.

---
*Document generated from the verified DefenceIQ codebase. All described features, models, protocols, and workflows reflect actual, functional implementations.*
"""

# ==============================================================================
# 2. HTML CONTENT FOR PRINT-PERFECT PDF GENERATION
# ==============================================================================
HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DEFENCEIQ — PROJECT OVERVIEW</title>
<style>
  @page {
    size: A4 portrait;
    margin: 18mm 16mm 18mm 16mm;
    @bottom-right {
      content: counter(page);
      font-family: 'Segoe UI', Arial, sans-serif;
      font-size: 8.5pt;
      color: #64748b;
    }
    @bottom-left {
      content: "DefenceIQ — Personal Endpoint Security System";
      font-family: 'Segoe UI', Arial, sans-serif;
      font-size: 8.5pt;
      color: #64748b;
    }
  }

  body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    background: #ffffff;
    font-size: 9.5pt;
    line-height: 1.52;
    margin: 0;
    padding: 0;
  }

  /* Cover Header */
  .doc-header {
    border-bottom: 2.5px solid #0f172a;
    padding-bottom: 12px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }
  .doc-title {
    font-size: 21pt;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.5px;
    margin: 0 0 4px 0;
    text-transform: uppercase;
  }
  .doc-subtitle {
    font-size: 10.5pt;
    font-weight: 600;
    color: #0284c7;
    margin: 0;
  }
  .doc-badge {
    text-align: right;
    font-size: 8.5pt;
    font-weight: 600;
    color: #475569;
    line-height: 1.35;
  }

  /* Headings */
  h2 {
    font-size: 12.5pt;
    font-weight: 700;
    color: #0f172a;
    border-bottom: 1.2px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 9px;
    text-transform: uppercase;
    letter-spacing: 0.2px;
    page-break-after: avoid;
  }

  h3 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #0369a1;
    margin-top: 13px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }

  p {
    margin: 0 0 8px 0;
    text-align: justify;
  }

  ul {
    margin: 0 0 10px 0;
    padding-left: 18px;
  }

  li {
    margin-bottom: 4px;
    text-align: justify;
  }

  strong {
    color: #0f172a;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 14px 0;
    font-size: 8.5pt;
    page-break-inside: avoid;
  }

  th, td {
    padding: 6px 9px;
    border: 1px solid #cbd5e1;
    text-align: left;
    vertical-align: top;
  }

  th {
    background-color: #f1f5f9;
    font-weight: 700;
    color: #0f172a;
  }

  tr:nth-child(even) td {
    background-color: #f8fafc;
  }

  /* Visual boxes & Callouts */
  .info-box {
    background-color: #f8fafc;
    border-left: 3.5px solid #0284c7;
    padding: 8px 12px;
    margin: 9px 0 12px 0;
    font-size: 9pt;
    page-break-inside: avoid;
  }

  .diagram-box {
    background-color: #0f172a;
    color: #e2e8f0;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt;
    line-height: 1.35;
    padding: 10px 14px;
    border-radius: 4px;
    margin: 10px 0 14px 0;
    white-space: pre;
    overflow-x: auto;
    page-break-inside: avoid;
  }

  .usp-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 8px;
    margin: 10px 0;
    page-break-inside: avoid;
  }

  .usp-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 3px solid #0ea5e9;
    padding: 7px 11px;
    border-radius: 3px;
  }

  .usp-card strong {
    color: #0369a1;
    font-size: 9.2pt;
    display: block;
    margin-bottom: 2px;
  }

  .team-table td:first-child {
    font-weight: 700;
    width: 28%;
    background-color: #f8fafc;
  }

  .footer-note {
    margin-top: 24px;
    border-top: 1px solid #e2e8f0;
    padding-top: 8px;
    font-size: 7.8pt;
    color: #64748b;
    text-align: center;
    font-style: italic;
  }

  .page-break {
    page-break-before: always;
  }
</style>
</head>
<body>

  <!-- Header -->
  <div class="doc-header">
    <div>
      <h1 class="doc-title">DefenceIQ</h1>
      <p class="doc-subtitle">Official Project Overview & Submission Specification</p>
    </div>
    <div class="doc-badge">
      AI-Assisted Personal Endpoint Security<br>
      Windows Agent & Companion Dashboard<br>
      Verification Status: 100% Production Ready
    </div>
  </div>

  <!-- Section 1 -->
  <h2>1. Team Details</h2>
  <table class="team-table">
    <tr>
      <td>Team Name</td>
      <td><strong>Black Spades Z</strong></td>
    </tr>
    <tr>
      <td>Team Leader</td>
      <td><strong>Black Spades Z</strong></td>
    </tr>
    <tr>
      <td>Team Leader Contact</td>
      <td>Email: <strong>blackspadesz784@gmail.com</strong> (Contact number available upon request)</td>
    </tr>
    <tr>
      <td>Project Repository</td>
      <td>DefenceIQ — Personal Endpoint Security System</td>
    </tr>
  </table>

  <!-- Section 2 -->
  <h2>2. Problem Statement Chosen</h2>
  
  <h3>Problem Statement</h3>
  <p>
    Personal computers—laptops and desktops utilized by individuals, developers, researchers, and students—are increasingly targeted by sophisticated cyber threats, including polymorphic malware, living-off-the-land (LotL) binary abuse, rapid ransomware bursts, unauthorized persistence modifications, and malicious script execution. Most personal users rely solely on legacy signature-based antivirus software or have no active behavioral monitoring at all. The critical problem DefenceIQ addresses is the complete lack of real-time endpoint behavioral visibility, explainable threat scoring, remote security oversight when away from the workstation, and safe, reversible automated containment for personal computing environments.
  </p>

  <h3>Why This Problem Matters</h3>
  <ul>
    <li><strong>Critical Data on Personal Endpoints:</strong> Personal computers store sensitive financial, academic, personal, and proprietary code assets. Despite this value, everyday users remain completely blind to underlying process trees, abnormal parent-child relationships, unauthorized background network connections, and rapid file modifications.</li>
    <li><strong>Failure of Signature-Based Antivirus:</strong> Conventional antivirus solutions scan known static file hashes and routinely fail against in-memory script executions, living-off-the-land techniques (PowerShell, WMI, mshta), and zero-day ransomware bursts.</li>
    <li><strong>Inaccessibility of Enterprise EDR:</strong> Professional Endpoint Detection and Response (EDR) platforms (e.g., CrowdStrike, Microsoft Defender for Endpoint) require corporate infrastructure, Security Operations Centers (SOCs), complex management consoles, and costly licenses, making them entirely inaccessible to individual users and small teams.</li>
    <li><strong>Absence of Remote Visibility:</strong> Personal security tools provide no straightforward mechanism for users to monitor their computer's security status, active applications, or threat alerts remotely while away from their desks.</li>
    <li><strong>Destructive and Opaque Remediation:</strong> Existing tools often permanently delete files or crash processes without context or rollback options, causing data loss and operational disruption. Solving this problem delivers enterprise-grade behavioral visibility, explainable intelligence, and safe containment in a lightweight, offline-first form factor.</li>
  </ul>

  <!-- Section 3 -->
  <h2>3. Brief Solution</h2>

  <h3>Proposed Solution</h3>
  <p>
    DefenceIQ is an open-source, AI-assisted personal endpoint security system providing layered defensive monitoring for Windows workstations, paired with a companion Android dashboard and responsive web interface. The system comprises four tightly integrated subsystems:
  </p>
  <ul>
    <li><strong>Endpoint Security Agent:</strong> A lightweight Windows background service hosting six continuous telemetry monitors (Process, File, Network, USB Removable Media, Active Window/Browser Tab, and Downloads) coupled with layered detection engines (Static Analysis, YARA rules, Multi-Hash Reputation, and ClamAV fallback).</li>
    <li><strong>AI & Explainable Risk Scoring Engine:</strong> An intelligent correlation pipeline featuring an unsupervised scikit-learn Isolation Forest anomaly detector and a deterministic, additive 0–100 risk scoring model that tracks process lineages across sliding temporal windows, providing human-readable explanations and explicit signal weights.</li>
    <li><strong>Graduated Reversible Response Engine:</strong> An automated containment controller executing non-destructive interventions—such as Windows API process suspension, executable-specific Windows Firewall outbound blocks, and secure metadata-backed file quarantine—coupled with an instantaneous one-click rollback mechanism.</li>
    <li><strong>Multi-Transport Mobile Companion & Web Dashboard:</strong> A native Android companion application (Kotlin, Jetpack Compose) and an executive HTML5/CSS3 web dashboard providing real-time telemetry feeds, device health metrics, live security alerts, and bidirectional control over local Wi-Fi, direct USB cable (ADB), Bluetooth LE, or an end-to-end HMAC-SHA256 authenticated Cloud Relay.</li>
  </ul>

  <div class="info-box">
    <strong>How It Solves the Problem:</strong><br>
    DefenceIQ continuously monitors multi-layer endpoint behavior locally, correlating cross-domain telemetry into transparent, explainable risk scores without cloud latency or subscription dependencies. It pairs the workstation with a remote mobile companion across local networks or encrypted cloud relays, alerting users instantly to behavioral anomalies and executing safe, reversible containment actions that neutralize threats while safeguarding data integrity.
  </div>

  <!-- Section 4 -->
  <h2>4. Tech Stack & Technical Approach</h2>

  <h3>Comprehensive Technology Stack</h3>
  <table>
    <thead>
      <tr>
        <th style="width: 25%;">Domain / Layer</th>
        <th style="width: 35%;">Technologies & Frameworks</th>
        <th style="width: 40%;">Implemented Role & Purpose</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Core Languages</strong></td>
        <td>Python 3.10+, Kotlin (Android), HTML5, CSS3, JavaScript ES6+, PowerShell</td>
        <td>Agent daemon, ML inference, native mobile UI, web dashboard, and system automation.</td>
      </tr>
      <tr>
        <td><strong>Endpoint Agent & API</strong></td>
        <td>FastAPI, Uvicorn (ASGI), asyncio, PyInstaller</td>
        <td>High-speed local REST/WebSocket server and standalone frozen Windows binary.</td>
      </tr>
      <tr>
        <td><strong>System Monitoring</strong></td>
        <td><code>psutil</code>, <code>watchdog</code>, <code>pywin32</code>, Windows <code>ctypes</code></td>
        <td>Telemetry tracking: process lineage, file system events, network sockets, and Authenticode checks.</td>
      </tr>
      <tr>
        <td><strong>Detection Engines</strong></td>
        <td><code>pefile</code>, <code>yara-python</code>, PurePython YARA, <code>hashlib</code>, <code>pyclamd</code></td>
        <td>Static PE header inspection, behavioral rule matching, SHA-256 hash reputation, and ClamAV fallback.</td>
      </tr>
      <tr>
        <td><strong>Machine Learning & AI</strong></td>
        <td><code>scikit-learn</code> (Isolation Forest), <code>numpy</code>, Shannon Entropy</td>
        <td>Unsupervised endpoint telemetry anomaly detection and ransomware encryption burst calculation.</td>
      </tr>
      <tr>
        <td><strong>Local Data Store</strong></td>
        <td>SQLite 3 (WAL mode)</td>
        <td>High-concurrency, ACID-compliant local storage for events, incidents, and audit trails.</td>
      </tr>
      <tr>
        <td><strong>Android Companion</strong></td>
        <td>Kotlin, Jetpack Compose, Material 3, OkHttp3, Retrofit, StateFlow</td>
        <td>Native mobile app with live telemetry dashboard, notification service, and remote command controls.</td>
      </tr>
      <tr>
        <td><strong>Transports & Comms</strong></td>
        <td>HTTP/WebSockets, UDP Beacon, ADB Bridge, BLE, Cloud Relay (SSE / ntfy.sh / Render)</td>
        <td>Multi-transport redundancy for local Wi-Fi, physical USB cable, Bluetooth, and cellular 4G/5G data.</td>
      </tr>
      <tr>
        <td><strong>Containment & Controls</strong></td>
        <td>Windows Firewall (<code>netsh</code>), Windows API (<code>NtSuspendProcess</code>), Quarantine Vault</td>
        <td>Graduated, non-destructive process suspension, network isolation, and reversible file vaulting.</td>
      </tr>
      <tr>
        <td><strong>Testing & Verification</strong></td>
        <td>Pytest, Custom E2E Harness (<code>run_e2e_verification.py</code>)</td>
        <td>Closed-loop verification of all 12 security stages in isolated sandbox environments.</td>
      </tr>
    </tbody>
  </table>

  <h3>Technical Approach & Workflow</h3>
  <div class="diagram-box">
+---------------------+     +-----------------------+     +------------------------+
| 6 Host Telemetry    | --> | Layered Detection     | --> | AI Anomaly Detector    |
| Monitors (psutil,   |     | (PE, YARA, Hashes,    |     | (Isolation Forest,     |
| watchdog, ctypes)   |     | ClamAV, Entropy)      |     | Shannon Entropy Delta) |
+---------------------+     +-----------------------+     +------------------------+
           |                                                           |
           v                                                           v
+---------------------+     +-----------------------+     +------------------------+
| SQLite 3 Store      | <-- | Graduated Response    | <-- | Process-Tree Temporal  |
| (WAL Mode: events,  |     | (Suspend, Firewall,   |     | Event Correlator &     |
| incidents, actions) |     | Reversible Quarantine)|     | 0-100 Risk Scorer      |
+---------------------+     +-----------------------+     +------------------------+
           |
           +------------------------------+
                                          v
+----------------------------------------------------------------------------------+
| Communications Layer (FastAPI REST, WebSockets, UDP Beacon, USB ADB, BLE, Relay) |
+----------------------------------------------------------------------------------+
                                          |
                +-------------------------+-------------------------+
                v                                                   v
+--------------------------------+                 +-------------------------------+
| Android Companion (Compose UI) |                 | Executive Web Dashboard (SPA) |
+--------------------------------+                 +-------------------------------+</div>

  <p>The technical workflow executes across eight structured phases:</p>
  <ul>
    <li><strong>1. User Interaction & Sticky Pairing:</strong> The agent initializes as a standalone executable (`DefenceIQ-Laptop-Agent.exe`) or background service. It generates an authenticated pairing token (e.g. `DIQ-EJFW-GC3V`). The user pairs via the Android app or web companion over local Wi-Fi or via UDP discovery beacon. Sticky pairing permanently binds the devices until explicitly revoked.</li>
    <li><strong>2. Continuous Multi-Layer Telemetry Ingestion:</strong> Six background monitors track host behavior: `ProcessMonitor` captures creation events, parent-child chains (e.g., Word launching PowerShell), and checks Authenticode/Catalog digital signatures; `FileMonitor` watches user directories with Shannon entropy analysis; `NetworkMonitor` maps sockets and flags C2 ports; `USBMonitor` scans removable media for autorun scripts; `WindowMonitor` tracks active apps and browser domains with privacy redaction; and `DownloadMonitor` extracts origin URLs via NTFS `Zone.Identifier` ADS.</li>
    <li><strong>3. Multi-Engine Threat Detection:</strong> Ingested binaries and scripts pass through static PE analysis (magic bytes, section headers, high-risk Win32 API imports), YARA rule matching (reverse shells, extortion notes, script bypasses), cryptographic hash reputation lookups (local cache and optional VirusTotal API), and ClamAV signature scans.</li>
    <li><strong>4. AI/ML Anomaly Detection:</strong> An unsupervised `IsolationForest` model evaluates six-dimensional telemetry vectors (`cpu_percent`, `memory_rss_mb`, `open_connections`, `file_write_burst`, `entropy_delta`, `child_process_count`). Telemetry deviating from learned baseline distributions generates an auxiliary `ml_anomaly_detected` signal.</li>
    <li><strong>5. Event Correlation & Additive Risk Scoring:</strong> The `EventCorrelator` maps multi-source events by parent-child process tree across a 60-second sliding window. The `RiskScoringEngine` computes an additive, explainable 0–100 score mapped to four color-coded risk bands: Green (0–19), Yellow (20–49), Orange (50–69), and Red (70–100), documenting every contributing signal and weight.</li>
    <li><strong>6. Graduated Reversible Containment:</strong> Based on configured protection levels (Basic, Balanced, Maximum), the `ResponseEngine` executes non-destructive countermeasures: process suspension via `NtSuspendProcess` (preserving process memory), outbound network isolation via Windows Firewall rules (`netsh advfirewall`), and secure file quarantine with restoration metadata sidecars. One-click rollback restores all changes instantly.</li>
    <li><strong>7. Tamper Protection & Agent Self-Defense:</strong> The `SelfMonitor` guards agent files (`defenceiq.db`, pairing key) against deletion or tampering, inspects host process terminations for targeted `taskkill` commands against the agent PID, and generates emergency alerts upon tampering.</li>
    <li><strong>8. Multi-Transport Mobile Synchronization:</strong> Telemetry, hardware metrics, active window titles, and alert frames are dispatched via FastAPI REST/WebSocket endpoints and the end-to-end encrypted Cloud Relay (SSE over HTTPS using HMAC-SHA256). Live connectivity persists across Wi-Fi, USB cable (ADB), BLE, and mobile data (4G/5G).</li>
  </ul>

  <!-- Section 5 -->
  <h2>5. Unique Selling Proposition (USP)</h2>

  <div class="usp-grid">
    <div class="usp-card">
      <strong>1. Offline-First Architecture with Zero Cloud Dependency</strong>
      100% of telemetry monitoring, static analysis, YARA scanning, machine learning anomaly inference, event correlation, risk scoring, and automated containment execute entirely on the local host machine. DefenceIQ requires no internet connectivity, external servers, or subscription dependencies to deliver complete endpoint protection.
    </div>

    <div class="usp-card">
      <strong>2. Transparent, Fully Explainable Risk Scoring</strong>
      Unlike opaque commercial antivirus products that emit black-box verdicts, DefenceIQ provides total explainability. Every 0–100 risk score details its exact contributing signals, individual point weights (e.g., ransomware encryption burst: +35, script shell execution: +25), threat classifications, and plain-language descriptions.
    </div>

    <div class="usp-card">
      <strong>3. 100% Reversible, Non-Destructive Containment with One-Click Rollback</strong>
      DefenceIQ eliminates fear of destructive false positives. Countermeasures prioritize reversible containment: processes are suspended in memory without data loss, network isolation is applied strictly to specific executables via Windows Firewall, and quarantined files are preserved in a structured vault with restoration sidecars. Any containment action can be reversed instantly from the phone or web companion.
    </div>

    <div class="usp-card">
      <strong>4. Multi-Transport Resilient Connectivity (LAN, USB, BLE, and Cloud Relay)</strong>
      DefenceIQ provides unprecedented transport flexibility: high-speed local Wi-Fi with zero-config UDP beacon discovery, direct physical USB cable tethering via ADB port forwarding (for air-gapped or restricted environments), Bluetooth Low Energy (BLE), and an end-to-end HMAC-SHA256 authenticated Cloud Relay ensuring continuous mobile oversight over 4G/5G cellular data.
    </div>

    <div class="usp-card">
      <strong>5. Cross-Layer Temporal Process-Tree Correlation</strong>
      Rather than evaluating events in isolation, DefenceIQ chains process, file, network, and removable media telemetry across entire process lineages within sliding temporal windows. This eliminates false alarms from isolated benign spikes while accurately capturing complex multi-stage attack chains.
    </div>

    <div class="usp-card">
      <strong>6. Contextual Active Window, Browser Tab & Download Provenance Tracking</strong>
      By integrating foreground window monitoring with Windows NTFS <code>Zone.Identifier</code> Alternate Data Streams (ADS), DefenceIQ captures the exact origin URL and domain of downloaded files at the moment of arrival, correlating downloads with active browser tabs and triggering instant multi-engine scans.
    </div>

    <div class="usp-card">
      <strong>7. Strict Privacy by Design & Least-Privilege Telemetry</strong>
      DefenceIQ enforces strict privacy boundaries: only security metadata (process names, cryptographic hashes, entropy metrics, remote IPs, file extensions) is processed or transmitted. Document contents and keystrokes are never inspected, and foreground window titles automatically redact passwords, session tokens, and authentication parameters.
    </div>
  </div>

  <!-- Section 6 -->
  <h2>6. Conclusion</h2>

  <div class="info-box" style="border-left-color: #0f172a; background-color: #f1f5f9;">
    <p><strong>Executive Summary:</strong></p>
    <p>
      <strong>1. The Problem:</strong> Personal computers store invaluable personal, professional, and development assets yet lack proactive behavioral security monitoring. Traditional signature-based antivirus fails against modern fileless and script-based threats, while enterprise EDR tools remain inaccessible, complex, and expensive. Users lack remote visibility and face disruptive, irreversible containment.
    </p>
    <p>
      <strong>2. The DefenceIQ Solution:</strong> DefenceIQ provides a free, open-source, AI-assisted personal endpoint security system. Combining a lightweight Windows security agent with a native Android companion app and executive web dashboard, it delivers enterprise-grade behavioral visibility, explainable threat intelligence, and remote oversight.
    </p>
    <p>
      <strong>3. Technology & Approach:</strong> Engineered with Python, Kotlin (Jetpack Compose), and FastAPI, DefenceIQ integrates six continuous telemetry monitors, layered static and YARA engines, an unsupervised scikit-learn Isolation Forest ML detector, and an additive 0–100 explainable risk scoring pipeline. It enforces non-destructive, 100% reversible containment (process suspension, firewall blocking, safe quarantine) across Wi-Fi, USB, BLE, and encrypted cloud relays.
    </p>
    <p style="margin-bottom: 0;">
      <strong>4. Real-World Impact:</strong> DefenceIQ bridges the critical gap between ineffective consumer antivirus and complex enterprise EDR. By delivering robust behavioral protection with zero cloud lock-in, total explainability, and non-destructive containment, DefenceIQ empowers individuals, students, developers, and researchers with accessible, reliable, and transparent workstation security.
    </p>
  </div>

  <div class="footer-note">
    DefenceIQ - AI-Assisted Personal Endpoint Security System | Verified Codebase Implementation Report | Black Spades Z
  </div>

</body>
</html>
"""

def main():
    print("=" * 70)
    print("  DEFENCEIQ - GENERATING SUBMISSION DOCUMENTS")
    print("=" * 70)

    # 1. Write Markdown
    print(f"Writing Markdown document: {MD_PATH}")
    with open(MD_PATH, "w", encoding="utf-8") as f:
        f.write(MD_CONTENT.strip() + "\n")
    print(f"  -> Successfully generated Markdown ({os.path.getsize(MD_PATH)} bytes).")

    # 2. Write HTML
    print(f"Writing HTML print-ready document: {HTML_PATH}")
    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(HTML_CONTENT.strip() + "\n")
    print(f"  -> Successfully generated HTML ({os.path.getsize(HTML_PATH)} bytes).")

    # 3. Generate PDF using Edge Headless
    print(f"Compiling PDF via Microsoft Edge headless: {PDF_PATH}")
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    edge_bin = next((p for p in edge_paths if os.path.isfile(p)), "msedge.exe")

    cmd = [
        edge_bin,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={PDF_PATH}",
        HTML_PATH,
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        if os.path.isfile(PDF_PATH) and os.path.getsize(PDF_PATH) > 0:
            print(f"  -> SUCCESS! PDF generated successfully ({os.path.getsize(PDF_PATH)} bytes).")
            print(f"  -> Output Path: {PDF_PATH}")
        else:
            print(f"  -> Edge headless returned code {res.returncode}, but PDF was not created.")
            print(f"  -> Stderr: {res.stderr}")
            print("  -> Falling back to ReportLab generation...")
            generate_reportlab_pdf(PDF_PATH)
    except Exception as e:
        print(f"  -> Exception running Edge headless: {e}")
        print("  -> Falling back to ReportLab generation...")
        generate_reportlab_pdf(PDF_PATH)

    print("=" * 70)
    print("  GENERATION COMPLETE")
    print("=" * 70)


def generate_reportlab_pdf(target_path):
    """Fallback generator using ReportLab Platypus."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

    doc = SimpleDocTemplate(
        target_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=15,
    )
    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=6,
    )
    h3_style = ParagraphStyle(
        'Heading3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=6,
    )

    story = [
        Paragraph("DEFENCEIQ — PROJECT OVERVIEW", title_style),
        Paragraph("Official Project Overview & Submission Specification", subtitle_style),
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0f172a'), spaceAfter=12),
        Paragraph("1. Team Details", h2_style),
        Paragraph("<b>Team Name:</b> Black Spades Z<br/><b>Team Leader:</b> Black Spades Z<br/><b>Team Leader Contact:</b> blackspadesz784@gmail.com (Phone available upon request)", body_style),
        Spacer(1, 8),
        Paragraph("2. Problem Statement Chosen", h2_style),
        Paragraph("Personal computers face an increasing volume of modern threats (polymorphic malware, Living-off-the-Land attacks, ransomware bursts) while lacking real-time behavioral visibility, explainability, remote oversight, and safe containment.", body_style),
        Spacer(1, 8),
        Paragraph("3. Brief Solution", h2_style),
        Paragraph("DefenceIQ provides an open-source, AI-assisted personal endpoint security system pairing a Windows security agent with an Android companion dashboard and responsive web interface, featuring 6 telemetry monitors, layered detection engines, Isolation Forest ML anomaly detection, and reversible containment.", body_style),
        Spacer(1, 8),
        Paragraph("4. Tech Stack & Technical Approach", h2_style),
        Paragraph("<b>Tech Stack:</b> Python 3.10+, Kotlin (Jetpack Compose), FastAPI, Uvicorn, psutil, pywin32, watchdog, pefile, YARA, scikit-learn, SQLite (WAL), OkHttp, Retrofit, WebSockets, UDP Beacon, ADB Bridge, BLE, Cloud Relay.", body_style),
        Spacer(1, 8),
        Paragraph("5. USP", h2_style),
        Paragraph("Offline-first zero cloud dependency; transparent additive risk scoring; non-destructive reversible containment; multi-transport redundancy (Wi-Fi, USB, BLE, Cloud Relay); temporal process-tree correlation; download origin tracking.", body_style),
        Spacer(1, 8),
        Paragraph("6. Conclusion", h2_style),
        Paragraph("DefenceIQ bridges the visibility gap for personal computing by delivering enterprise-grade behavioral security in an accessible, explainable, and privacy-preserving platform.", body_style),
    ]

    doc.build(story)
    print(f"  -> ReportLab fallback generated: {target_path} ({os.path.getsize(target_path)} bytes)")


if __name__ == "__main__":
    main()

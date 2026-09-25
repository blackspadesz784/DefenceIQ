# Project Overview — AI-Powered Personal Security Layer

---

## Project Name

**AI-Powered Personal Security Layer**

---

## One-Line Description

A lightweight, AI-assisted security agent for personal laptops and desktops that monitors system behavior, detects suspicious activity, and provides remote visibility through an Android mobile dashboard.

---

## Problem Statement

Personal computers — laptops and desktops used by individuals, students, developers, and researchers — are increasingly targeted by malware, ransomware, spyware, and persistent threats. Most people either rely entirely on a single commercial antivirus product or have no active security monitoring at all.

The fundamental gap is **visibility**:

- Users do not see what processes are running or what network connections are being made in real time.
- Antivirus products use primarily signature-based detection and frequently miss novel, behavior-based, or fileless threats.
- There is no straightforward way for a non-expert user to monitor their computer's security posture remotely — for example, while away from their desk.
- When a threat occurs, users have no context about what happened, when it happened, or what the system did in response.

---

## Why This Problem Matters

- **Home and personal computers hold sensitive data**: documents, credentials, financial information, code, and personal files.
- **Sophisticated attacks no longer require sophisticated targets**: commodity malware, phishing, and ransomware kits target everyday users.
- **Signature-based detection alone is insufficient**: polymorphic malware, fileless attacks, and living-off-the-land (LotL) techniques bypass signature scanners routinely.
- **Users are blind to their own security posture**: most users have no way of knowing whether their system is behaving normally without expert knowledge.
- **Remote visibility is absent in personal security tools**: commercial solutions rarely offer simple, real-time remote dashboards designed for individual use.

---

## Proposed Solution

The **AI-Powered Personal Security Layer** is a personal security system composed of three integrated components:

### 1. Laptop/Desktop Security Agent

A background software agent running on the user's personal computer that:

- Continuously monitors system telemetry (processes, files, network, persistence, scripts).
- Applies a multi-layer detection pipeline: rule-based detection → behavioral analysis → AI/ML-based detection.
- Calculates a real-time risk score for the device.
- Generates structured security alerts when suspicious behavior is detected.
- Performs conservative, controlled defensive actions (e.g., alerting, process termination upon confirmation) when supported.
- Operates in a reduced offline mode when the internet is unavailable.

### 2. Backend / API Layer

A server-side component that:

- Receives telemetry events and security alerts from registered devices.
- Stores security history, events, and risk scores in a database.
- Exposes a REST API for the mobile dashboard.
- Handles authentication and device registration.
- Queues and delivers notifications to mobile clients.

### 3. Android Mobile Dashboard

A mobile application that allows the user to remotely monitor their computer's security status:

- Real-time and historical security event feed.
- Current risk score and device status.
- Threat alerts and notifications.
- Overview of actions taken by the agent.

---

## Project Objectives

1. Build a functional laptop security agent capable of monitoring key system telemetry on Windows.
2. Implement a multi-layer detection pipeline combining rule-based, behavioral, and AI/ML detection methods.
3. Develop a backend API that aggregates security events from monitored devices.
4. Build an Android mobile dashboard that presents security information clearly and intuitively.
5. Ensure the system remains partially functional offline and synchronizes when connectivity is restored.
6. Document the design, limitations, and decisions clearly and honestly.
7. Produce a working MVP suitable for hackathon demonstration and further development.

---

## Target Users

| User Type | Description |
|---|---|
| **Primary** | Security-aware individuals who want more visibility into their personal computer's activity |
| **Secondary** | Developers and students who want to understand system behavior and learn about endpoint security |
| **Tertiary** | Small teams or households with shared devices where one person monitors security |

**This product is NOT designed for:**

- Enterprise endpoint management.
- Replacing professional EDR solutions (CrowdStrike, Carbon Black, etc.).
- Corporate IT environments.
- Managed security service providers (MSSPs).

---

## Major Use Cases

| ID | Use Case | Description |
|---|---|---|
| UC-01 | Real-time process monitoring | Agent detects a new unknown process and evaluates whether it is suspicious. |
| UC-02 | Malicious script detection | Agent detects a PowerShell script executing with suspicious arguments. |
| UC-03 | Ransomware-like behavior detection | Agent observes rapid, unexpected mass file modifications in user directories. |
| UC-04 | Persistence attempt detection | Agent detects a new entry added to Windows startup registry keys. |
| UC-05 | Suspicious network connection | Agent detects a process making an outbound connection to an unusual IP or port. |
| UC-06 | Remote dashboard review | User views the day's security events and current risk score on their Android phone. |
| UC-07 | Alert notification | User receives a push notification when a high-severity threat is detected. |
| UC-08 | Offline operation | The laptop loses internet access; the agent continues monitoring locally and queues events. |
| UC-09 | Event synchronization | Internet is restored; the agent synchronizes queued events to the backend. |
| UC-10 | Risk score history | User reviews the risk score trend over the past week via the mobile dashboard. |

---

## Core System Components

```
┌──────────────────────────────────────────────────────────────┐
│                   Laptop Security Agent                       │
│                                                              │
│  ┌────────────┐  ┌───────────────┐  ┌───────────────────┐   │
│  │ Monitoring │→ │Feature Extract│→ │  Detection Engine  │   │
│  │   Layer    │  │    Module     │  │(Rules + AI + Score)│   │
│  └────────────┘  └───────────────┘  └────────┬──────────┘   │
│                                               │              │
│                                     ┌─────────▼──────────┐  │
│                                     │   Alert Manager &  │  │
│                                     │  Response Engine   │  │
│                                     └─────────┬──────────┘  │
└───────────────────────────────────────────────┼─────────────┘
                                                │ HTTPS
                              ┌─────────────────▼──────────────────┐
                              │           Backend API               │
                              │     (FastAPI + PostgreSQL)          │
                              └─────────────────┬──────────────────┘
                                                │ REST / Push
                              ┌─────────────────▼──────────────────┐
                              │        Android Mobile App           │
                              │     (Flutter — Security Dashboard)  │
                              └────────────────────────────────────┘
```

---

## High-Level Workflow

```
System event occurs on laptop
        ↓
Monitoring layer captures telemetry
        ↓
Feature extraction normalizes raw data
        ↓
Rule-based engine evaluates known patterns
        ↓
AI/behavioral engine evaluates anomalies
        ↓
Risk score is updated
        ↓
Alert generated if threshold exceeded
        ↓
Optional: controlled defensive response
        ↓
Event sent to backend (if online) or queued (if offline)
        ↓
Mobile dashboard reflects updated status
        ↓
User receives notification (if high severity)
```

---

## Project Scope

### In Scope (MVP)

- Windows 10/11 laptop agent.
- Process monitoring and process behavior.
- File system activity monitoring (selected directories).
- Network connection monitoring.
- Persistence/startup change detection.
- Script and command execution monitoring.
- Rule-based detection with a curated initial ruleset.
- Basic AI/ML anomaly detection as a scoring component.
- Risk scoring (0–100 scale).
- Alert generation and local logging.
- Backend REST API with PostgreSQL storage.
- Android mobile dashboard (read-only: view events, risk score, alerts).
- JWT-based authentication between agent, backend, and mobile.
- Offline local monitoring with event queuing.
- Synchronization on reconnection.

### Out of Scope (MVP)

- macOS and Linux support (future phase).
- Automated blocking or quarantine without user confirmation (future phase).
- Full sandbox / dynamic malware analysis.
- Deep packet inspection or network traffic content analysis.
- iOS mobile application.
- Web dashboard (browser-based).
- Multi-device fleet management.
- Cloud-based AI inference (all AI inference is local in MVP).
- Vulnerability scanning or patch management.
- Password manager integration.
- Browser extension or web activity monitoring.

---

## MVP Definition

The Minimum Viable Product is a working end-to-end demonstration of:

1. A Windows laptop agent that monitors processes, files, network, and startup changes.
2. A basic detection pipeline with rule-based detection and a simple ML anomaly model.
3. Risk scoring that is updated continuously.
4. Alert generation for defined threat categories.
5. A FastAPI backend that receives events from the agent and stores them.
6. An Android mobile app that displays device status, current risk score, and recent security events.
7. Push or polling-based notifications for high-severity alerts.
8. Offline operation with synchronization when internet is restored.

The MVP does **not** need to:

- Detect every threat type.
- Have a polished production-grade UI.
- Have a fully trained ML model — a simple anomaly detection baseline is acceptable.
- Support multiple devices per user account.

---

## Future Scope

| Feature | Description |
|---|---|
| macOS support | Extend the agent to macOS with platform-specific monitoring. |
| Linux support | Extend the agent to Linux distributions. |
| Automated quarantine | Controlled quarantine of suspicious files with rollback capability. |
| Cloud AI inference | Send anonymized feature vectors to a cloud AI service for advanced analysis. |
| Threat intelligence integration | Cross-reference IPs, hashes, and domains against public threat intelligence feeds. |
| Web dashboard | Browser-based security dashboard as an alternative to the mobile app. |
| Vulnerability scanning | Check installed software versions against known CVE databases. |
| Multi-device support | Monitor multiple computers from a single mobile dashboard. |
| Advanced ML models | Retrain models on user-specific baseline behavior for improved accuracy. |
| iOS dashboard | iOS version of the mobile security dashboard. |
| YARA rule integration | Support custom YARA rules for file-based detection. |

---

## Expected Outcome

By the end of this project:

- A personal laptop will have an always-on security agent that provides behavioral visibility beyond what a standard antivirus offers.
- The user will be able to see their computer's security status from their Android phone at any time.
- When unusual behavior occurs, the user will receive a contextualized alert — not just a raw log entry — explaining what was observed and why it was flagged.
- The detection approach will be honest about its limitations: it will reduce the chance of missing threats, but it will not claim perfect detection.
- The project will serve as both a functional security tool and a clear educational demonstration of endpoint security concepts.

---

*Document version: 1.0 | Last updated: 2026-09-16*

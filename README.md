# DefenceIQ — AI-Assisted Personal Endpoint Security System

> Free, open-source, AI-assisted personal endpoint security system providing layered defensive monitoring for Windows laptops and desktops, paired with an Android companion dashboard over local Wi-Fi.

---

## ⚠️ Important Defensive Security Notice

DefenceIQ is a **defensive security system**:
- **Never contains real malware, exploits, or offensive payloads**: all validation uses inert behavioral simulations inside isolated test VMs.
- **Offline-First**: Detection, scoring, and containment loops operate 100% locally on the host machine with zero cloud or phone dependencies.
- **Reversible Containment**: Automated actions prioritize reversible containment (quarantine with restore metadata, process suspension, temporary firewall blocks) rather than destructive deletion.
- **Explainable Decisions**: Every risk score and automated response logs its specific contributing signals and weights.

---

## Architecture Overview

```
[Android Dashboard App] <---(local Wi-Fi/LAN, HTTP + WebSocket)---> [Laptop Security Agent]
                                                                            |
                                                                +-----------+-----------+
                                                                |  Monitoring Layer     |
                                                                |  - Process watcher    |
                                                                |  - File watcher       |
                                                                |  - Network watcher    |
                                                                +-----------+-----------+
                                                                            |
                                                                +-----------+-----------+
                                                                |  Detection Engine     |
                                                                |  - YARA / ClamAV      |
                                                                |  - Hash reputation    |
                                                                |  - Static analysis    |
                                                                +-----------+-----------+
                                                                            |
                                                                +-----------+-----------+
                                                                |  Risk Scoring Engine  |
                                                                |  - Event correlation  |
                                                                |  - Rule-based score   |
                                                                +-----------+-----------+
                                                                            |
                                                                +-----------+-----------+
                                                                |  Response Engine      |
                                                                |  - Firewall block     |
                                                                |  - Process isolate    |
                                                                |  - Quarantine         |
                                                                +-----------+-----------+
                                                                            |
                                                                +-----------+-----------+
                                                                |  Local Store (SQLite) |
                                                                |  - Event log          |
                                                                |  - Incident timeline  |
                                                                +-----------------------+
```

---

## Repository Structure

```
sentinellayer/
├── agent/                     # Laptop Security Agent (Python)
│   ├── monitors/
│   │   ├── process_monitor.py     # Milestone 1 - Phase 1
│   │   ├── file_monitor.py        # Milestone 1 - Phase 2
│   │   ├── network_monitor.py     # Milestone 1 - Phase 3
│   │   └── usb_monitor.py         # Milestone 2
│   ├── detection/
│   │   ├── signature_engine.py    # ClamAV wrapper
│   │   ├── yara_engine.py         # YARA rules engine
│   │   ├── reputation_engine.py   # Hash/signature reputation
│   │   └── static_analysis.py     # PE & entropy analysis
│   ├── ai_engine/
│   │   ├── event_correlator.py    # Multi-signal temporal correlation
│   │   ├── risk_scoring.py        # Additive explainable risk scoring
│   │   └── model/                 # Milestone 2 local ML anomaly models
│   ├── response/
│   │   ├── firewall_controller.py # Windows Firewall containment
│   │   ├── process_controller.py  # Process suspension & isolation
│   │   └── quarantine.py          # Reversible quarantine
│   ├── tamper_protection/
│   │   └── self_monitor.py        # Agent self-defense (Milestone 2)
│   ├── storage/
│   │   ├── db.py                  # SQLite event store
│   │   └── models.py              # Telemetry & incident models
│   ├── comms/
│   │   ├── local_server.py        # Local Wi-Fi HTTP + WebSocket server
│   │   ├── usb_bridge.py          # Milestone 2 (ADB port forward)
│   │   ├── bluetooth_bridge.py    # Milestone 2 (BLE)
│   │   └── cloud_relay.py         # Milestone 2 (Optional push)
│   ├── config/
│   │   └── settings.py            # Basic/Balanced/Maximum settings
│   ├── main.py                    # Service entry point
│   └── requirements.txt
├── android-app/                # Kotlin + Jetpack Compose companion app
│   ├── app/src/main/java/.../
│   │   ├── ui/dashboard/
│   │   ├── ui/alerts/
│   │   ├── ui/history/
│   │   ├── ui/settings/
│   │   ├── data/
│   │   └── network/
│   └── build.gradle
├── test-harness/                # SAFE simulated scenarios (VM only)
│   ├── simulate_process_chain.py
│   ├── simulate_mass_file_change.py
│   └── README_SAFETY.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── RISK_SCORING.md
│   └── SETUP.md
└── README.md
```

---

## Free & Open-Source Stack

| Component | Tool / Library |
|---|---|
| Process & Telemetry | `psutil`, `pywin32`, `watchdog` |
| Digital Signature Check | WinTrust / Authenticode API |
| Containment | Windows Firewall (`netsh`), Process Job / Suspension |
| Local Server | `FastAPI`, `uvicorn`, `websockets` |
| Local Storage | SQLite (`sqlite3`) |
| Android Companion | Kotlin, Jetpack Compose, Room |

---

## Current Status: Milestone 1 — Phase 1 (Process Monitoring)

Phase 1 provides real-time process monitoring tracking process creation, parent/child relationships, Authenticode digital signature status, resource spikes, and structured JSON event dispatching to the internal event bus.

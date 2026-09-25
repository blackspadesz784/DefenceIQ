# Development Plan — AI-Powered Personal Security Layer

---

## Overview

This document defines the phased development roadmap. Each phase has a clear objective, task list, dependencies, expected output, and definition of done.

**MVP Milestone** is marked explicitly. Everything up to and including Phase 8 constitutes the MVP.

---

## 🏁 MVP Milestone

> **MVP = Phases 1 through 8 complete.**
>
> A working end-to-end system with:
> - Windows laptop agent monitoring processes, files, network, startup, and script execution
> - Rule-based + AI anomaly detection with risk scoring and alert generation
> - FastAPI backend receiving events and serving an API
> - Android mobile dashboard showing security status, risk score, and alerts
> - Push notifications for high-severity alerts
> - Offline operation with synchronization

---

## Phase 1 — Project Setup

### Objective
Establish the complete project infrastructure: repository, code quality tools, environment setup, CI basics, and documentation structure.

### Tasks
- [ ] Create Git repository with correct branch structure (see [GIT_WORKFLOW.md](GIT_WORKFLOW.md))
- [ ] Set up `docs/` with all documentation files (this phase)
- [ ] Create stub directories: `agent/`, `ai/`, `backend/`, `mobile/`, `tests/`
- [ ] Configure Python environment for agent: `pyproject.toml` or `requirements.txt`, `ruff`, `black`, `mypy`, `pre-commit`
- [ ] Configure Python environment for backend: same tooling
- [ ] Set up Flutter project in `mobile/`
- [ ] Write `.gitignore` for Python, Flutter, and `.env` files
- [ ] Write `.env.example` template for backend
- [ ] Set up `pre-commit` hooks for linting and formatting

### Dependencies
None — this is the foundation phase.

### Expected Output
- Fully configured repository with correct structure
- Pre-commit hooks enforcing code quality
- Empty but properly structured component directories
- All documentation files in `docs/`

### Definition of Done
- `git commit` succeeds with pre-commit hooks passing
- All documentation files exist and are non-empty
- `.gitignore` prevents secrets or venv directories from being committed

---

## Phase 2 — Laptop Monitoring Layer

### Objective
Implement all five telemetry collection monitors on Windows.

### Tasks
- [ ] Implement `ProcessMonitor`: psutil-based process enumeration and creation/termination detection
- [ ] Implement `FileMonitor`: watchdog-based file system event collection for configured directories
- [ ] Implement `NetworkMonitor`: psutil `net_connections()` polling with process correlation
- [ ] Implement `StartupMonitor`: Windows Registry Run key monitoring with `winreg`; Startup folder monitoring
- [ ] Implement `CommandMonitor`: Process creation interception for scripting hosts with argument capture
- [ ] Write unit tests for each monitor with mocked OS data
- [ ] Implement agent `config.yaml` loading with Pydantic validation
- [ ] Implement agent operational logger

### Dependencies
Phase 1 complete.

### Expected Output
- Five working monitor modules that produce structured telemetry dictionaries
- Unit tests covering normal and edge cases

### Definition of Done
- All five monitors produce correctly structured telemetry events when run on a Windows test machine
- Unit tests pass
- CPU usage of running monitors is measured and confirmed < 5% on idle test system

---

## Phase 3 — Telemetry Pipeline (Feature Extraction)

### Objective
Transform raw monitor output into normalized feature vectors ready for detection.

### Tasks
- [ ] Define the canonical feature schema (list of all features, types, ranges)
- [ ] Implement `FeatureExtractor` that consumes raw telemetry and produces feature dicts
- [ ] Implement process feature extraction: `is_signed_binary`, `path_legitimacy_score`, `parent_process_type`, `process_tree_depth`
- [ ] Implement file feature extraction: event rate computation, extension mismatch, executable detection
- [ ] Implement network feature extraction: port categorization, process-to-connection association
- [ ] Implement command feature extraction: `has_encoded_args`, `has_download_cradle`, `has_bypass_flags`
- [ ] Implement feature normalization to 0–1 ranges
- [ ] Write unit tests for feature extraction with known inputs and expected outputs
- [ ] Implement local SQLite schema and `DatabaseManager`
- [ ] Implement `offline_queue` table logic

### Dependencies
Phase 2 complete.

### Expected Output
- Feature extractor that converts any telemetry dict to a consistent feature vector
- Local SQLite database with correct schema

### Definition of Done
- Given a known raw telemetry input, the extractor produces the correct feature vector
- Unit tests for all feature extractors pass
- SQLite database creates and reads correctly

---

## Phase 4 — Rule-Based Detection Engine

### Objective
Implement the rule engine and an initial ruleset covering the most important detection patterns.

### Tasks
- [ ] Define YAML rule schema with fields: rule_id, name, severity, score_contribution, conditions (field + operator + value), logic (AND/OR)
- [ ] Implement `RuleEngine` that loads all YAML rule files from `detection/rules/`
- [ ] Implement condition evaluation for all required operators: equals, contains, contains_any, greater_than, less_than, is_true
- [ ] Implement compound condition logic (AND / OR)
- [ ] Write initial ruleset:
  - `process_rules.yaml`: suspicious parent-child, headless process in temp
  - `script_rules.yaml`: PowerShell encoded, PowerShell download cradle, mshta invocation
  - `file_rules.yaml`: mass file modification rate, double extension, executable in temp
  - `network_rules.yaml`: unusual port, no-UI process connecting externally
  - `persistence_rules.yaml`: new Run key, Run key in temp, unsigned startup entry
- [ ] Implement `RiskScorer` with weighted score aggregation and time decay
- [ ] Write unit tests for each rule category with matching and non-matching inputs

### Dependencies
Phase 3 complete.

### Expected Output
- Working rule engine that returns matched rules and score contributions
- Initial 15–20 detection rules covering the most important patterns
- Risk scorer that aggregates signals into a 0–100 score

### Definition of Done
- Given feature vectors designed to match each rule, all rules fire correctly
- Given normal feature vectors, no rules fire (no false positives in tests)
- Risk score produces expected values for known inputs

---

## Phase 5 — AI/ML Detection

### Objective
Train an Isolation Forest anomaly model and integrate it into the detection pipeline.

### Tasks
- [ ] Define `feature_config.yaml` with canonical feature list matching Phase 3 implementation
- [ ] Write a data collection script that records benign telemetry feature vectors to a CSV
- [ ] Collect at minimum 2–4 hours of benign telemetry on a normal-use Windows system
- [ ] Implement preprocessing pipeline: StandardScaler, categorical encoding, NaN filling
- [ ] Train Isolation Forest model with `contamination=0.05`
- [ ] Evaluate model on held-out benign data: false positive rate < 10%
- [ ] Serialize model + scaler + feature config to `ai/models/anomaly_model_v1.joblib`
- [ ] Implement `AIEngine` class that loads the model at startup and provides `score(feature_vector)` method
- [ ] Integrate `AIEngine` into the agent pipeline (runs in background thread, non-blocking)
- [ ] Implement graceful fallback: if model load fails, detection continues rule-based only
- [ ] Write experiment log entry in `ai/experiments/experiment_log.md`

### Dependencies
Phase 3 complete (feature extraction defines the input format); Phase 4 can run in parallel.

### Expected Output
- Trained Isolation Forest model with < 10% false positive rate on benign held-out data
- `AIEngine` class integrated into the detection pipeline

### Definition of Done
- Model serializes and deserializes correctly
- Given a normal feature vector, anomaly score is < 0.5
- Given an artificially extreme feature vector, anomaly score is > 0.7
- Agent runs with AI engine loaded without performance impact

---

## Phase 6 — Backend / API

### Objective
Build the FastAPI backend with all required endpoints, database schema, and authentication.

### Tasks
- [ ] Set up FastAPI project with Uvicorn, SQLAlchemy, Alembic, Pydantic
- [ ] Design and create all Alembic migrations for the PostgreSQL schema
- [ ] Implement user registration and login endpoints with bcrypt + JWT
- [ ] Implement device registration and device token issuance
- [ ] Implement heartbeat endpoint
- [ ] Implement security event submission endpoint (single and batch)
- [ ] Implement risk score submission and retrieval endpoints
- [ ] Implement alert retrieval endpoints
- [ ] Implement sync state endpoint
- [ ] Implement response action retrieval endpoint
- [ ] Implement health check endpoint
- [ ] Implement rate limiting
- [ ] Write backend unit tests for all endpoints (using `httpx` test client)
- [ ] Write `.env.example` with all required environment variables documented
- [ ] Verify all endpoints against API_SPEC.md

### Dependencies
Phase 1 (project setup); Phase 3 (event format definition).

### Expected Output
- Running FastAPI backend on local development server
- All endpoints returning correct responses per API_SPEC.md
- PostgreSQL database with all tables created

### Definition of Done
- All API endpoint unit tests pass
- Backend accepts events from a test agent and stores them correctly
- Swagger UI (auto-generated by FastAPI) matches API_SPEC.md contract

---

## Phase 7 — Mobile Dashboard

### Objective
Build the Android mobile app with all MVP screens.

### Tasks
- [ ] Set up Flutter project with required dependencies: `dio`, `flutter_secure_storage`, FCM plugin
- [ ] Implement login screen with JWT authentication
- [ ] Implement API service layer with `dio` (all required GET endpoints)
- [ ] Implement Dashboard screen: risk score gauge, device status, last 5 alerts
- [ ] Implement Alerts screen: paginated list of alerts with severity badges
- [ ] Implement Event Detail screen: full event information
- [ ] Implement History screen: risk score chart (7-day trend)
- [ ] Implement state management (Provider or Riverpod)
- [ ] Implement FCM push notification handling
- [ ] Implement secure JWT token storage and refresh logic
- [ ] Test mobile app against the Phase 6 backend
- [ ] Write Flutter widget tests for main screens

### Dependencies
Phase 6 complete (backend API must be running).

### Expected Output
- Android APK that connects to the backend, authenticates, and displays security data
- Push notifications received for High/Critical alerts

### Definition of Done
- All four screens display correct data from the backend
- Push notification received and displays alert correctly
- Login and session refresh work correctly

---

## Phase 8 — Alert System and End-to-End Integration

### Objective
Complete the alert pipeline from agent detection to mobile notification and verify end-to-end flow.

### Tasks
- [ ] Implement `AlertManager` with deduplication logic
- [ ] Implement `SyncManager` with online/offline detection and event queue management
- [ ] Implement `APIClient` in the agent for authenticated HTTPS communication to backend
- [ ] Implement offline event queuing: write to `offline_queue` SQLite table when backend unreachable
- [ ] Implement sync-on-reconnect: transmit queued events in chronological order on connectivity restore
- [ ] Implement heartbeat from agent to backend every 60 seconds
- [ ] Integrate backend `NotificationService` to trigger FCM push for High/Critical alerts
- [ ] End-to-end test: simulate suspicious activity → agent detects → alert generated → backend receives → push notification delivered → mobile app displays alert
- [ ] End-to-end test: disconnect agent from internet → monitor continues → reconnect → queue syncs correctly

### Dependencies
Phases 4, 5, 6, and 7 complete.

### Expected Output
- Complete end-to-end pipeline working for the MVP

### Definition of Done
- A simulated suspicious event causes an alert to appear on the mobile device within 30 seconds
- After 5 minutes of offline operation, all events sync correctly on reconnection
- Risk score displayed on mobile matches agent's local risk score

---

## Phase 9 — Controlled Response Engine

> **Post-MVP Phase**

### Objective
Implement the first controlled response capability: process flagging and user-initiated action confirmation.

### Tasks
- [ ] Implement `ResponseEngine` in the agent with `PROCESS_FLAGGED` action type
- [ ] Implement response action reporting to the backend
- [ ] Implement user-initiated action endpoint in the backend (Phase 2 API)
- [ ] Implement action request UI in the mobile app (acknowledge/dismiss alert)

### Dependencies
Phase 8 complete.

---

## Phase 10 — Integration Testing

### Objective
Comprehensive integration and scenario-based testing across all components.

### Tasks
- [ ] Write integration test: agent ↔ backend event submission and retrieval
- [ ] Write integration test: offline queue and sync
- [ ] Write integration test: mobile dashboard data accuracy
- [ ] Write detection scenario tests: simulate each rule category and verify alert generation
- [ ] Write false-positive test scenarios: verify legitimate behavior does not trigger alerts
- [ ] Performance test: measure agent CPU and RAM under load
- [ ] Performance test: backend API response times under concurrent load

### Dependencies
Phase 8 complete.

---

## Phase 11 — Testing, Documentation, and Stabilization

### Objective
Ensure all components are tested, documented, and stable before demo or release.

### Tasks
- [ ] Complete all unit tests for each component
- [ ] Complete all integration tests
- [ ] Review and update all `docs/` documentation for accuracy
- [ ] Fix all discovered bugs from Phase 10
- [ ] Measure and verify resource constraints (CPU < 2%, RAM < 150 MB)
- [ ] Write setup and installation guide for demo

### Dependencies
Phase 10 complete.

---

## Phase 12 — Deployment and Demo

### Objective
Deploy the backend to a cloud environment and prepare a working demo.

### Tasks
- [ ] Choose cloud hosting platform (Railway / Render / Fly.io)
- [ ] Create `Dockerfile` for backend
- [ ] Create `docker-compose.yml` for local development environment (backend + PostgreSQL)
- [ ] Deploy backend and PostgreSQL to chosen cloud platform
- [ ] Configure environment variables in cloud platform
- [ ] Build and install Android APK on demo phone
- [ ] Install agent on demo laptop
- [ ] Register device and verify end-to-end pipeline in cloud environment
- [ ] Create demo scenario: simulate suspicious activity, show alert appear on mobile phone
- [ ] Update DEPLOYMENT.md with actual deployment steps

### Dependencies
Phase 11 complete.

---

## Timeline Summary

| Phase | Description | MVP |
|---|---|---|
| 1 | Project Setup | ✅ |
| 2 | Laptop Monitoring Layer | ✅ |
| 3 | Telemetry Pipeline | ✅ |
| 4 | Rule-Based Detection | ✅ |
| 5 | AI/ML Detection | ✅ |
| 6 | Backend / API | ✅ |
| 7 | Mobile Dashboard | ✅ |
| 8 | Alert System + E2E Integration | ✅ **← MVP Milestone** |
| 9 | Controlled Response Engine | Phase 2 |
| 10 | Integration Testing | Phase 2 |
| 11 | Testing + Stabilization | Phase 2 |
| 12 | Deployment + Demo | Phase 2 |

---

*Document version: 1.0 | Last updated: 2026-09-16*

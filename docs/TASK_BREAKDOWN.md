# Task Breakdown — AI-Powered Personal Security Layer

---

## Overview

Tasks are organized by component. Each task includes a description, dependencies, priority, and expected deliverable.

**Priority levels:**
- **P0** — Blocking; nothing else can proceed without this
- **P1** — High priority; required for MVP
- **P2** — Important but not blocking MVP
- **P3** — Phase 2 or future

---

## 1. Laptop Agent Tasks

### AGENT-001 — Project bootstrap and config loading

| Field | Value |
|---|---|
| **Description** | Create the `agent/` directory structure; implement `config.yaml` with Pydantic validation; implement the agent entry point `main.py` with initialization and shutdown logic |
| **Dependency** | None |
| **Priority** | P0 |
| **Deliverable** | `agent/main.py` runs, loads config, and exits cleanly |

---

### AGENT-002 — Process Monitor

| Field | Value |
|---|---|
| **Description** | Implement `ProcessMonitor` using `psutil`. Poll running processes every configurable interval. Detect process creation and termination. Produce structured telemetry dicts with PID, PPID, name, exe, cmdline, username, start_time. |
| **Dependency** | AGENT-001 |
| **Priority** | P1 |
| **Deliverable** | `monitoring/process_monitor.py` produces correctly structured process events on Windows |

---

### AGENT-003 — File Monitor

| Field | Value |
|---|---|
| **Description** | Implement `FileMonitor` using `watchdog`. Watch configured directories. Capture CREATE, MODIFY, DELETE, RENAME events with path and timestamp. Compute SHA-256 for new/modified executables. |
| **Dependency** | AGENT-001 |
| **Priority** | P1 |
| **Deliverable** | `monitoring/file_monitor.py` captures file events from watched directories |

---

### AGENT-004 — Network Monitor

| Field | Value |
|---|---|
| **Description** | Implement `NetworkMonitor` using `psutil.net_connections()`. Poll on configurable interval. Correlate connections to process names. Detect new connections since last poll. |
| **Dependency** | AGENT-001 |
| **Priority** | P1 |
| **Deliverable** | `monitoring/network_monitor.py` produces network connection events associated with process names |

---

### AGENT-005 — Startup / Persistence Monitor

| Field | Value |
|---|---|
| **Description** | Implement `StartupMonitor` using `winreg`. Monitor HKCU and HKLM Run keys. Monitor Startup folder. Detect additions, modifications, and deletions. |
| **Dependency** | AGENT-001 |
| **Priority** | P1 |
| **Deliverable** | `monitoring/startup_monitor.py` detects changes to Windows persistence locations |

---

### AGENT-006 — Command / Script Monitor

| Field | Value |
|---|---|
| **Description** | Implement `CommandMonitor`. Intercept process creation events for known scripting hosts. Capture command-line arguments. Flag encoded arguments, download cradle patterns, bypass flags. |
| **Dependency** | AGENT-002 (process monitor used as a source) |
| **Priority** | P1 |
| **Deliverable** | `monitoring/command_monitor.py` detects scripting host invocations with structured output |

---

### AGENT-007 — Feature Extraction Pipeline

| Field | Value |
|---|---|
| **Description** | Implement `FeatureExtractor`. Consume raw telemetry from all monitors. Produce normalized feature vectors per the canonical feature schema. Implement each feature computation function. |
| **Dependency** | AGENT-002 through AGENT-006 |
| **Priority** | P1 |
| **Deliverable** | `extraction/extractor.py` transforms any raw telemetry dict into a complete feature vector |

---

### AGENT-008 — Rule Engine

| Field | Value |
|---|---|
| **Description** | Implement `RuleEngine`. Load all YAML rule files from `detection/rules/`. Evaluate feature vectors against all rules. Return list of matched rules, severity, and score contributions. |
| **Dependency** | AGENT-007 |
| **Priority** | P1 |
| **Deliverable** | `detection/rule_engine.py` with working rule evaluation and the initial 15–20 rule YAML files |

---

### AGENT-009 — AI Engine Integration

| Field | Value |
|---|---|
| **Description** | Implement `AIEngine`. Load pre-trained model from `ai/models/`. Provide `score(feature_vector)` method. Run inference in background thread. Implement graceful fallback if model is unavailable. |
| **Dependency** | AGENT-007; AI-003 (model must be trained) |
| **Priority** | P1 |
| **Deliverable** | `detection/ai_engine.py` with working inference and fallback |

---

### AGENT-010 — Risk Scorer

| Field | Value |
|---|---|
| **Description** | Implement `RiskScorer`. Accept rule match results and AI anomaly score. Compute composite score (0–100). Implement time decay. Persist score history to SQLite. |
| **Dependency** | AGENT-008, AGENT-009 |
| **Priority** | P1 |
| **Deliverable** | `scoring/risk_scorer.py` producing correct scores for known inputs |

---

### AGENT-011 — Alert Manager

| Field | Value |
|---|---|
| **Description** | Implement `AlertManager`. Generate structured alerts when risk score crosses thresholds or critical rules fire. Implement deduplication. Persist alerts to SQLite. |
| **Dependency** | AGENT-010 |
| **Priority** | P1 |
| **Deliverable** | `alerts/alert_manager.py` generating correctly structured alerts |

---

### AGENT-012 — Local SQLite Database

| Field | Value |
|---|---|
| **Description** | Implement SQLite schema and `DatabaseManager`. Create all tables: `local_events`, `local_alerts`, `offline_queue`, `risk_score_history`, `sync_state`. |
| **Dependency** | AGENT-001 |
| **Priority** | P1 |
| **Deliverable** | `storage/database.py` with all tables created and basic CRUD operations |

---

### AGENT-013 — Sync Manager and API Client

| Field | Value |
|---|---|
| **Description** | Implement `SyncManager`. Detect internet connectivity. Send events in real-time when online. Queue events in `offline_queue` when offline. Sync queue on reconnection using batch endpoint. Implement heartbeat. |
| **Dependency** | AGENT-011, AGENT-012, BACKEND-006 |
| **Priority** | P1 |
| **Deliverable** | `sync/sync_manager.py` with working online/offline mode switching and queue sync |

---

### AGENT-014 — Response Engine (MVP: logging only)

| Field | Value |
|---|---|
| **Description** | Implement `ResponseEngine`. In MVP, only logs response recommendations and creates `PROCESS_FLAGGED` action records. No process termination. |
| **Dependency** | AGENT-011 |
| **Priority** | P2 |
| **Deliverable** | `response/responder.py` with logging-only response behavior |

---

## 2. AI/ML Tasks

### AI-001 — Feature Configuration Definition

| Field | Value |
|---|---|
| **Description** | Define `ai/training/feature_config.yaml` with the canonical feature list, types, and normalization parameters. Must match the agent's feature extractor exactly. |
| **Dependency** | AGENT-007 (feature extractor defines the schema) |
| **Priority** | P1 |
| **Deliverable** | `feature_config.yaml` with complete feature specification |

---

### AI-002 — Benign Data Collection

| Field | Value |
|---|---|
| **Description** | Run the agent in data-collection mode on a normal-use Windows system for 2–4 hours. Record feature vectors to a CSV file. Cover: web browsing, coding, document editing, file management, idle. |
| **Dependency** | AGENT-007 |
| **Priority** | P1 |
| **Deliverable** | CSV file of at least 5,000 benign feature vectors |

---

### AI-003 — Model Training and Evaluation

| Field | Value |
|---|---|
| **Description** | Implement preprocessing pipeline (StandardScaler, encoding, NaN fill). Train Isolation Forest with contamination=0.05. Evaluate on held-out benign data. Target false positive rate < 10%. Serialize model to `anomaly_model_v1.joblib`. |
| **Dependency** | AI-001, AI-002 |
| **Priority** | P1 |
| **Deliverable** | `ai/models/anomaly_model_v1.joblib` with < 10% FPR; experiment log entry |

---

### AI-004 — Supervised Classifier (Phase 2)

| Field | Value |
|---|---|
| **Description** | Collect labeled malicious samples (controlled environment). Train XGBoost or Random Forest classifier. Evaluate precision, recall, F1. Replace or augment Isolation Forest. |
| **Dependency** | AI-003, labeled dataset |
| **Priority** | P3 |
| **Deliverable** | Phase 2 classifier model with evaluation metrics |

---

## 3. Backend Tasks

### BACKEND-001 — FastAPI Project Setup

| Field | Value |
|---|---|
| **Description** | Create FastAPI project structure. Configure Uvicorn. Set up SQLAlchemy + Alembic. Configure Pydantic settings from environment variables. |
| **Dependency** | None |
| **Priority** | P0 |
| **Deliverable** | Running FastAPI server on localhost with health endpoint returning 200 |

---

### BACKEND-002 — Database Schema and Migrations

| Field | Value |
|---|---|
| **Description** | Create all SQLAlchemy models. Generate and apply Alembic migrations for all tables: users, refresh_tokens, devices, security_events, alerts, risk_scores, response_actions. |
| **Dependency** | BACKEND-001 |
| **Priority** | P1 |
| **Deliverable** | PostgreSQL database with all tables and indexes created via Alembic |

---

### BACKEND-003 — Authentication (User)

| Field | Value |
|---|---|
| **Description** | Implement user registration, login, JWT issuance, refresh token rotation, and logout endpoints. bcrypt password hashing. |
| **Dependency** | BACKEND-002 |
| **Priority** | P1 |
| **Deliverable** | Working `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout` endpoints |

---

### BACKEND-004 — Device Registration and Auth

| Field | Value |
|---|---|
| **Description** | Implement device registration endpoint. Issue device token on registration. Implement device token validation middleware. |
| **Dependency** | BACKEND-003 |
| **Priority** | P1 |
| **Deliverable** | Working `/devices/register` endpoint and device token authentication |

---

### BACKEND-005 — Security Event Ingestion

| Field | Value |
|---|---|
| **Description** | Implement single event and batch event POST endpoints. Validate event schema. Store events in PostgreSQL. Implement duplicate event ID handling (idempotent). |
| **Dependency** | BACKEND-004 |
| **Priority** | P1 |
| **Deliverable** | Working `/events` and `/events/batch` endpoints |

---

### BACKEND-006 — Heartbeat, Device Status, and Sync State

| Field | Value |
|---|---|
| **Description** | Implement heartbeat endpoint that updates `devices.last_seen` and `current_risk_score`. Implement `/sync/state` endpoint for offline sync initialization. |
| **Dependency** | BACKEND-004 |
| **Priority** | P1 |
| **Deliverable** | Working heartbeat and sync state endpoints |

---

### BACKEND-007 — Dashboard Data Endpoints

| Field | Value |
|---|---|
| **Description** | Implement GET endpoints for mobile dashboard: device list, device detail, events (paginated), alerts (paginated), risk score, risk score history, event detail, response actions. |
| **Dependency** | BACKEND-005 |
| **Priority** | P1 |
| **Deliverable** | All GET endpoints returning correct, paginated data |

---

### BACKEND-008 — Push Notification Service

| Field | Value |
|---|---|
| **Description** | Implement FCM push notification dispatch. On High/Critical alert received, trigger FCM notification to the user's registered FCM token. |
| **Dependency** | BACKEND-007 |
| **Priority** | P1 |
| **Deliverable** | Backend sends FCM push on Critical/High alert; mobile receives notification |

---

## 4. Mobile Tasks

### MOBILE-001 — Flutter Project Setup

| Field | Value |
|---|---|
| **Description** | Set up Flutter project. Add dependencies: `dio`, `flutter_secure_storage`, FCM plugin, charting library. Configure Android build. |
| **Dependency** | None |
| **Priority** | P0 |
| **Deliverable** | Flutter app compiles and runs on an Android emulator |

---

### MOBILE-002 — Authentication and API Service

| Field | Value |
|---|---|
| **Description** | Implement login screen. Implement `APIService` with `dio`. Implement JWT storage with `flutter_secure_storage`. Implement token refresh logic. |
| **Dependency** | MOBILE-001, BACKEND-003 |
| **Priority** | P1 |
| **Deliverable** | User can log in and the app stores the JWT securely |

---

### MOBILE-003 — Dashboard Screen

| Field | Value |
|---|---|
| **Description** | Implement Dashboard screen with: risk score gauge widget, device status indicator, last 5 alerts summary. Pull data from backend API. |
| **Dependency** | MOBILE-002, BACKEND-007 |
| **Priority** | P1 |
| **Deliverable** | Dashboard screen displays live data from backend |

---

### MOBILE-004 — Alerts and Event Detail Screens

| Field | Value |
|---|---|
| **Description** | Implement Alerts screen with paginated alert list and severity badges. Implement Event Detail screen with full event information. |
| **Dependency** | MOBILE-002, BACKEND-007 |
| **Priority** | P1 |
| **Deliverable** | User can browse alerts and drill down to event details |

---

### MOBILE-005 — Risk Score History Chart

| Field | Value |
|---|---|
| **Description** | Implement History screen with a time-series chart of the last 7 days of risk scores. Use a Flutter charting library. |
| **Dependency** | MOBILE-002, BACKEND-007 |
| **Priority** | P1 |
| **Deliverable** | History screen shows a risk score trend chart |

---

### MOBILE-006 — Push Notification Handling

| Field | Value |
|---|---|
| **Description** | Integrate FCM plugin. Handle push notifications: show system notification with alert ID and severity. On tap, navigate to Event Detail screen. |
| **Dependency** | MOBILE-002, BACKEND-008 |
| **Priority** | P1 |
| **Deliverable** | Push notification received, displayed, and tapped to navigate correctly |

---

## 5. Database Tasks

### DB-001 — PostgreSQL Schema Design Review

| Field | Value |
|---|---|
| **Description** | Review the schema defined in DATABASE_SCHEMA.md against the API_SPEC.md before writing any ORM models. Verify all required fields, indexes, and relationships are consistent. |
| **Dependency** | DATABASE_SCHEMA.md, API_SPEC.md |
| **Priority** | P0 |
| **Deliverable** | Schema reviewed and confirmed consistent with API contract |

---

### DB-002 — SQLite Schema for Agent

| Field | Value |
|---|---|
| **Description** | Implement SQLite table definitions for the local agent database. Verify schema matches what AGENT-013 requires for the offline queue. |
| **Dependency** | AGENT-012 |
| **Priority** | P1 |
| **Deliverable** | SQLite schema in place and tested |

---

## 6. Security Tasks

### SEC-001 — JWT Implementation Review

| Field | Value |
|---|---|
| **Description** | Review and verify the JWT implementation: correct signing algorithm (HS256), correct claim validation (exp, iat, jti), no token in URL params, refresh rotation implemented. |
| **Dependency** | BACKEND-003 |
| **Priority** | P1 |
| **Deliverable** | JWT implementation confirmed secure against common misconfigurations |

---

### SEC-002 — Input Validation Audit

| Field | Value |
|---|---|
| **Description** | Audit all backend API endpoints for correct Pydantic validation. Verify max lengths, field types, and JSONB payload validation. |
| **Dependency** | BACKEND-007 |
| **Priority** | P1 |
| **Deliverable** | All endpoints validated; no unvalidated fields accepted |

---

### SEC-003 — Secrets Audit

| Field | Value |
|---|---|
| **Description** | Verify that no secrets (JWT key, DB credentials, FCM key, device token) are committed to Git. Verify `.env.example` documents all required variables without actual values. |
| **Dependency** | BACKEND-001 |
| **Priority** | P1 |
| **Deliverable** | Git history clean of secrets; `.gitignore` correct |

---

## 7. Testing Tasks

### TEST-001 — Agent Unit Tests

| Field | Value |
|---|---|
| **Description** | Write `pytest` unit tests for all agent modules: monitors (mocked OS), feature extractor, rule engine, risk scorer, alert manager. |
| **Dependency** | AGENT-008 through AGENT-011 |
| **Priority** | P1 |
| **Deliverable** | `agent/tests/` with test coverage for all core modules |

---

### TEST-002 — Backend Unit Tests

| Field | Value |
|---|---|
| **Description** | Write `pytest` tests for all backend endpoints using `httpx` test client. Cover: normal operation, validation errors, auth failures, not-found responses. |
| **Dependency** | BACKEND-007 |
| **Priority** | P1 |
| **Deliverable** | `backend/tests/` with tests for all endpoints |

---

### TEST-003 — Detection Scenario Tests

| Field | Value |
|---|---|
| **Description** | Write tests that simulate known attack patterns as feature vectors and verify each relevant rule fires and the risk score reaches the expected level. |
| **Dependency** | AGENT-008, AGENT-010 |
| **Priority** | P1 |
| **Deliverable** | Detection scenario test suite in `tests/e2e/` |

---

### TEST-004 — Offline Mode and Sync Integration Test

| Field | Value |
|---|---|
| **Description** | Write integration test that: (1) disables agent's network access, (2) simulates events, (3) verifies events are queued, (4) restores network, (5) verifies events sync correctly and appear in backend. |
| **Dependency** | AGENT-013, BACKEND-005 |
| **Priority** | P1 |
| **Deliverable** | Integration test in `tests/integration/test_offline_mode.py` |

---

## 8. Integration Tasks

### INT-001 — Agent ↔ Backend End-to-End

| Field | Value |
|---|---|
| **Description** | Run agent against a local backend. Verify events appear in the backend database. Verify heartbeat updates `devices.last_seen`. |
| **Dependency** | AGENT-013, BACKEND-006 |
| **Priority** | P1 |
| **Deliverable** | Manual and automated verification of agent-backend pipeline |

---

### INT-002 — Full E2E: Laptop → Backend → Mobile

| Field | Value |
|---|---|
| **Description** | Simulate a suspicious event on the laptop. Verify: alert generated locally → transmitted to backend → mobile app displays alert → push notification received. |
| **Dependency** | INT-001, MOBILE-006, BACKEND-008 |
| **Priority** | P1 |
| **Deliverable** | Documented E2E test result |

---

*Document version: 1.0 | Last updated: 2026-09-16*

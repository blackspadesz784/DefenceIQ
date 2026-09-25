# Project Structure — AI-Powered Personal Security Layer

---

## Repository Root

```
AI-Personal-Security-Layer/
│
├── README.md                         ← Project entry point; overview and navigation
│
├── docs/                             ← All project documentation
│
├── agent/                            ← Laptop/desktop security agent
│
├── ai/                               ← AI/ML model training and inference
│
├── backend/                          ← Backend REST API server
│
├── mobile/                           ← Android mobile dashboard (Flutter)
│
└── tests/                            ← Shared and cross-component test suites
```

> **Principle:** Source code directories are separated by component. Each component is independently developable and testable. Shared utilities live in the component that owns them or in a `shared/` directory if cross-component.

---

## Detailed Directory Structure

### `docs/` — Documentation

All project documentation. No application source code belongs here.

```
docs/
├── DOCUMENTATION_INDEX.md       ← Master index of all docs + reading order
├── PROJECT_OVERVIEW.md          ← Project concept, goals, scope
├── REQUIREMENTS.md              ← Functional and non-functional requirements
├── TECH_STACK.md                ← Technology selection and rationale
├── ARCHITECTURE.md              ← System architecture and component design
├── PROJECT_STRUCTURE.md         ← This file
├── FEATURES.md                  ← MVP, Phase 2, and future feature list
├── DETECTION_LOGIC.md           ← Detection pipeline specification
├── AI_MODEL.md                  ← AI/ML approach, training, inference
├── DATA_FLOW.md                 ← End-to-end data flow
├── API_SPEC.md                  ← REST API contract
├── DATABASE_SCHEMA.md           ← Database schema design
├── SECURITY.md                  ← Security design
├── THREAT_MODEL.md              ← Threat model (STRIDE-based)
├── PRIVACY.md                   ← Privacy-by-design document
├── DEVELOPMENT_PLAN.md          ← Phased development roadmap
├── TASK_BREAKDOWN.md            ← Task list by component
├── GIT_WORKFLOW.md              ← Git branching and collaboration rules
├── TESTING_STRATEGY.md          ← Testing approach and test categories
├── DEPLOYMENT.md                ← Deployment guide (local, demo, production)
├── LIMITATIONS.md               ← Honest limitations of the system
└── DECISIONS.md                 ← Architecture Decision Records (ADRs)
```

---

### `agent/` — Laptop Security Agent

The background Python process running on the user's Windows laptop.

```
agent/
│
├── main.py                       ← Agent entry point; initialization and lifecycle
├── config.yaml                   ← Agent configuration (monitoring scope, thresholds)
├── requirements.txt              ← Python dependencies for the agent
│
├── monitoring/                   ← Telemetry collection modules
│   ├── __init__.py
│   ├── process_monitor.py        ← Process creation, termination, and enumeration
│   ├── file_monitor.py           ← File system event monitoring (watchdog)
│   ├── network_monitor.py        ← Network connection polling (psutil)
│   ├── startup_monitor.py        ← Windows startup/persistence monitoring
│   └── command_monitor.py        ← Script and command-line execution monitoring
│
├── extraction/                   ← Feature extraction and normalization
│   ├── __init__.py
│   ├── extractor.py              ← Main feature extraction pipeline
│   ├── process_features.py       ← Process-specific feature extraction
│   ├── file_features.py          ← File-specific feature extraction
│   ├── network_features.py       ← Network-specific feature extraction
│   └── normalizer.py             ← Feature normalization for ML input
│
├── detection/                    ← Detection engine
│   ├── __init__.py
│   ├── rule_engine.py            ← Rule-based detection logic
│   ├── rules/                    ← YAML rule definitions
│   │   ├── process_rules.yaml
│   │   ├── file_rules.yaml
│   │   ├── network_rules.yaml
│   │   ├── persistence_rules.yaml
│   │   └── script_rules.yaml
│   └── ai_engine.py              ← AI/ML inference integration
│
├── scoring/                      ← Risk scoring
│   ├── __init__.py
│   └── risk_scorer.py            ← Risk score computation and decay
│
├── alerts/                       ← Alert management
│   ├── __init__.py
│   ├── alert_manager.py          ← Alert generation and deduplication
│   └── alert_models.py           ← Alert data models (Pydantic)
│
├── response/                     ← Response engine
│   ├── __init__.py
│   └── responder.py              ← Controlled response actions
│
├── sync/                         ← Backend communication and synchronization
│   ├── __init__.py
│   ├── sync_manager.py           ← Manages online/offline mode and sync
│   ├── api_client.py             ← HTTPS client for backend API
│   └── queue_manager.py          ← Local event queue management
│
├── storage/                      ← Local data persistence
│   ├── __init__.py
│   ├── database.py               ← SQLite connection and setup
│   └── models.py                 ← SQLAlchemy/SQLite table models
│
└── utils/                        ← Shared utilities
    ├── __init__.py
    ├── logger.py                 ← Agent operational logging
    ├── config_loader.py          ← Config file loading and validation
    └── crypto.py                 ← Local encryption utilities
```

---

### `ai/` — AI/ML Detection Engine

Model training scripts, datasets, evaluation, and the serialized model used by the agent.

```
ai/
│
├── README.md                     ← AI component documentation entry point
│
├── models/                       ← Serialized trained models (joblib)
│   └── anomaly_model_v1.joblib   ← MVP Isolation Forest model
│
├── training/                     ← Model training pipeline
│   ├── train.py                  ← Training entry point
│   ├── preprocess.py             ← Data preprocessing and feature engineering
│   ├── evaluate.py               ← Model evaluation and metrics
│   └── feature_config.yaml       ← Feature definitions for training/inference parity
│
├── data/                         ← Training datasets (NOT committed to Git if large)
│   ├── README.md                 ← Describes data sources and format; actual data excluded
│   ├── benign/                   ← Benign system behavior samples
│   └── malicious/                ← Malicious behavior samples (labeled, Phase 2)
│
├── notebooks/                    ← Exploratory analysis (Jupyter notebooks)
│   └── exploration.ipynb
│
└── experiments/                  ← Experiment logs and comparison results
    └── experiment_log.md
```

> **Note:** Raw training data is NOT committed to the repository. The `data/README.md` documents data sources and how to obtain or generate them. Only model artifacts (serialized `.joblib` files) and training scripts are committed.

---

### `backend/` — Backend API Server

The FastAPI Python application serving as the central API.

```
backend/
│
├── main.py                       ← FastAPI application entry point
├── requirements.txt              ← Python dependencies
├── alembic.ini                   ← Alembic migration configuration
│
├── app/
│   ├── __init__.py
│   │
│   ├── api/                      ← REST API route handlers
│   │   ├── __init__.py
│   │   ├── auth.py               ← Authentication endpoints
│   │   ├── devices.py            ← Device registration and status
│   │   ├── events.py             ← Security event ingestion and retrieval
│   │   ├── alerts.py             ← Alert endpoints
│   │   ├── risk_score.py         ← Risk score endpoints
│   │   ├── history.py            ← Security history endpoints
│   │   ├── actions.py            ← Response action endpoints
│   │   └── health.py             ← Health check
│   │
│   ├── auth/                     ← Authentication logic
│   │   ├── __init__.py
│   │   ├── jwt_handler.py        ← JWT creation and validation
│   │   ├── device_auth.py        ← Device token management
│   │   └── password.py           ← Password hashing (bcrypt)
│   │
│   ├── models/                   ← SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── event.py
│   │   ├── alert.py
│   │   ├── risk_score.py
│   │   └── action.py
│   │
│   ├── schemas/                  ← Pydantic request/response schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── event.py
│   │   ├── alert.py
│   │   └── risk_score.py
│   │
│   ├── services/                 ← Business logic
│   │   ├── __init__.py
│   │   ├── event_service.py      ← Event processing logic
│   │   ├── alert_service.py      ← Alert management
│   │   ├── device_service.py     ← Device management
│   │   └── notification_service.py ← Push notification dispatch
│   │
│   ├── db/                       ← Database setup and session
│   │   ├── __init__.py
│   │   ├── session.py            ← SQLAlchemy session factory
│   │   └── base.py               ← Base model class
│   │
│   └── core/                     ← App-wide configuration
│       ├── __init__.py
│       ├── config.py             ← Settings (loaded from env vars)
│       └── logging.py            ← Structured logging setup
│
├── migrations/                   ← Alembic migration scripts
│   └── versions/
│
└── .env.example                  ← Environment variable template (no secrets)
```

---

### `mobile/` — Android Mobile Dashboard

The Flutter application for the Android security dashboard.

```
mobile/
│
├── pubspec.yaml                  ← Flutter project configuration and dependencies
├── README.md                     ← Mobile component setup guide
│
├── lib/
│   ├── main.dart                 ← App entry point
│   │
│   ├── screens/                  ← Full screens / pages
│   │   ├── login_screen.dart
│   │   ├── dashboard_screen.dart
│   │   ├── alerts_screen.dart
│   │   ├── event_detail_screen.dart
│   │   └── history_screen.dart
│   │
│   ├── widgets/                  ← Reusable UI components
│   │   ├── risk_score_gauge.dart
│   │   ├── alert_card.dart
│   │   ├── event_list_item.dart
│   │   ├── device_status_card.dart
│   │   └── severity_badge.dart
│   │
│   ├── services/                 ← API and notification services
│   │   ├── api_service.dart      ← dio-based HTTP client
│   │   ├── auth_service.dart     ← JWT management
│   │   └── notification_service.dart ← FCM handler
│   │
│   ├── models/                   ← Dart data models
│   │   ├── device.dart
│   │   ├── security_event.dart
│   │   ├── alert.dart
│   │   └── risk_score.dart
│   │
│   └── providers/                ← State management
│       ├── dashboard_provider.dart
│       ├── alerts_provider.dart
│       └── auth_provider.dart
│
├── android/                      ← Android-specific configuration
└── assets/                       ← Icons, images, fonts
```

---

### `tests/` — Test Suites

Integration and end-to-end tests that cross component boundaries.

```
tests/
│
├── README.md                     ← Testing guide
│
├── integration/                  ← Integration tests (agent ↔ backend)
│   ├── test_agent_sync.py        ← Tests event queuing and sync
│   ├── test_api_endpoints.py     ← Tests all API endpoints
│   └── test_offline_mode.py      ← Tests offline behavior and reconnection
│
├── e2e/                          ← End-to-end scenario tests
│   ├── test_alert_flow.py        ← Simulates detection → alert → backend → mobile
│   └── test_detection_scenarios.py ← Simulates known attack patterns
│
├── fixtures/                     ← Shared test data and fixtures
│   ├── sample_events.json
│   ├── sample_alerts.json
│   └── mock_processes.json
│
└── conftest.py                   ← Shared pytest configuration
```

> **Unit tests** for each component live inside the component's own directory (e.g., `agent/tests/`, `backend/tests/`) to keep them co-located with the code they test. The top-level `tests/` directory contains only integration and end-to-end tests.

---

## Design Principles Behind This Structure

| Principle | How it is applied |
|---|---|
| **Separation of concerns** | Each component (agent, ai, backend, mobile) is independently deployable and testable |
| **Modularity** | Detection rules are data (YAML), not code — swappable without code changes |
| **No unnecessary nesting** | Directories are created because they serve a clear, non-trivial purpose |
| **Test co-location** | Unit tests live beside the code they test; shared tests live in `tests/` |
| **Secrets not in source** | `.env.example` templates exist; actual `.env` files are gitignored |
| **Documentation in `docs/`** | No stray `.md` files at component roots except component-specific `README.md` for setup |
| **Data not in Git** | Training datasets are referenced but not stored in the repository |

---

*Document version: 1.0 | Last updated: 2026-09-16*

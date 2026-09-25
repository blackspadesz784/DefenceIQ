# Technology Stack — AI-Powered Personal Security Layer

---

## Overview

This document defines the technology stack for the AI-Powered Personal Security Layer.

**Important conventions in this document:**

- ✅ **SELECTED** — Technology has been chosen.
- ⚠️ **PROPOSED — NOT FINAL** — Under consideration; not yet finalized.
- ❌ **REJECTED** — Evaluated and ruled out, with reason.

No technology is marked as finalized unless it has been deliberately selected based on the evaluation criteria below.

---

## Selection Criteria

Every technology was evaluated against:

1. **Practical implementation** — Does it work well for this use case?
2. **Cross-platform considerations** — Can it support future macOS/Linux extensions?
3. **Development speed** — Can a small team implement it quickly?
4. **Security** — Does it introduce unnecessary risk?
5. **Maintainability** — Is it well-documented and actively maintained?
6. **Compatibility** — Does it integrate cleanly with other stack components?
7. **Low unnecessary complexity** — Does it avoid overengineering?

---

## 1. Laptop / Desktop Security Agent

### 1.1 Agent Programming Language

| Technology | Python 3.10+ |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Primary language for the laptop security agent. |
| **Why suitable** | Python has mature libraries for system monitoring (`psutil`, `watchdog`, `pywin32`), is cross-platform, supports rapid development, has excellent ML/AI ecosystem compatibility, and is easy to read and maintain. |
| **Alternatives considered** | Go (excellent for system agents, lower resource use, but slower to develop and smaller ML ecosystem); Rust (best performance and safety, but steep learning curve for a hackathon timeline); C++ (most power, most complexity). |
| **Limitations** | Higher memory and CPU footprint than compiled languages; GIL limits true multi-threading (use `asyncio` or multiprocessing for concurrency). |

---

### 1.2 System Monitoring Libraries

#### Process Monitoring

| Technology | `psutil` (Python) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Monitor running processes, CPU/memory per process, network connections, and disk activity. |
| **Why suitable** | Cross-platform, actively maintained, comprehensive process introspection, widely used in security tooling. |
| **Limitations** | Some APIs require elevated privileges; cannot intercept system calls directly (not a kernel-level monitor). |

#### File System Monitoring

| Technology | `watchdog` (Python) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Monitor file system events: creation, modification, deletion, rename in specified directories. |
| **Why suitable** | Cross-platform file system event API built on OS-level notifications (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows). Low-overhead event-driven model. |
| **Limitations** | Does not monitor all file system activity system-wide out of the box — must configure watched directories carefully to balance coverage vs. performance. |

#### Windows-Specific Monitoring

| Technology | `pywin32` / `winreg` (Python) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Access Windows Registry for startup/persistence monitoring; access Windows Event Log; Windows-specific process APIs. |
| **Why suitable** | Official Python Windows extension; provides direct access to Win32 APIs without a compiled driver. |
| **Limitations** | Windows-only; breaks cross-platform compatibility for these features — macOS/Linux will require separate implementations. |

#### Process Creation Events (Windows)

| Technology | `WMI` via `wmi` Python package or Windows ETW (Event Tracing for Windows) |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Capture process creation events in near-real time, including command-line arguments. |
| **Why suitable** | WMI process creation events are accessible from userspace; ETW provides kernel-level event feeds without a driver. |
| **Alternatives** | Poll `psutil` on a short interval (simpler, less real-time); use `pyevtx` for Event Log parsing. |
| **Limitations** | WMI has known reliability issues; ETW requires more implementation effort. Decision pending on WMI vs. periodic psutil polling for MVP. |

---

### 1.3 Agent Local Storage

| Technology | SQLite (via Python `sqlite3`) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Store security events, alerts, risk score history, and offline event queue locally on the laptop. |
| **Why suitable** | Serverless, zero-configuration, file-based, built into Python standard library, sufficient for single-device local storage. |
| **Limitations** | Not suitable for high-concurrency write-heavy workloads; not appropriate for multi-device or backend use. |

---

### 1.4 Agent Configuration

| Technology | YAML configuration files |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Store agent configuration, detection rule parameters, and thresholds. |
| **Why suitable** | Human-readable, widely used, supported by `PyYAML` and `pydantic`. |
| **Limitations** | No built-in schema validation — must validate with Pydantic models at load time. |

---

## 2. AI / ML Detection

### 2.1 ML Framework

| Technology | `scikit-learn` (Python) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Train and run the MVP anomaly detection model. |
| **Why suitable** | Industry-standard ML library, excellent for classical ML methods (Isolation Forest, Random Forest, One-Class SVM), fast inference, no GPU required, integrates directly with the Python agent. |
| **Alternatives considered** | PyTorch (powerful, but overkill for tabular anomaly detection); TensorFlow (same concern); XGBoost (excellent for supervised classification — consider for Phase 2). |
| **Limitations** | Scikit-learn models are not ideal for sequence-based behavioral analysis; they require feature engineering for tabular input. |

### 2.2 Data Processing

| Technology | `pandas` + `numpy` |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Feature extraction, data normalization, and preprocessing for the ML pipeline. |
| **Why suitable** | Standard data processing stack; well-integrated with scikit-learn. |
| **Limitations** | Pandas has higher memory overhead than numpy alone; acceptable for the scale of this project. |

### 2.3 Model Serialization

| Technology | `joblib` |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Serialize and load trained scikit-learn models for local inference. |
| **Why suitable** | Native scikit-learn serialization library; efficient for numpy-heavy objects. |
| **Limitations** | Joblib models must be loaded from the same Python environment; versioning must be managed carefully. |

### 2.4 Advanced ML (Future Phase)

| Technology | XGBoost / LightGBM |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Supervised threat classification in Phase 2 when labeled training data is available. |
| **Why suitable** | Excellent performance on tabular, structured security telemetry; well-studied in cybersecurity ML literature. |
| **Limitations** | Requires labeled training data (malicious vs. benign) — not available at MVP stage. |

---

## 3. Backend / API

### 3.1 Backend Language

| Technology | Python 3.10+ |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Implement the backend API server. |
| **Why suitable** | Shared language with the agent reduces context switching; Python is excellent for API development with FastAPI. |
| **Limitations** | Not the highest-performance backend language (Go or Rust would be faster at scale); acceptable for this project's scale. |

### 3.2 Backend Framework

| Technology | FastAPI |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Build the REST API for the backend. |
| **Why suitable** | Async-native, automatic OpenAPI documentation, Pydantic data validation, high development speed, excellent documentation. Widely used in security tooling and data pipelines. |
| **Alternatives considered** | Django REST Framework (more batteries-included, heavier); Flask (lightweight but less structured); Node.js/Express (different language stack). |
| **Limitations** | FastAPI is ASGI-based; requires an ASGI server (Uvicorn) and may require additional setup for production (behind a reverse proxy). |

### 3.3 Database

| Technology | PostgreSQL 14+ |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Primary backend database for users, devices, security events, alerts, risk scores, and response actions. |
| **Why suitable** | Battle-tested relational database; excellent JSON support (JSONB) for flexible event payload storage; strong indexing; well-supported by Python ORMs. |
| **Alternatives considered** | MongoDB (flexible schema, but less relational integrity); SQLite (suitable for single-node development, not for production backend); MySQL (viable alternative, but PostgreSQL preferred for JSONB support). |
| **Limitations** | Requires a running PostgreSQL server; more operational overhead than SQLite. |

### 3.4 ORM

| Technology | SQLAlchemy 2.x + Alembic |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Database ORM (object-relational mapping) and schema migration management. |
| **Why suitable** | SQLAlchemy is the standard Python ORM; Alembic handles database migrations cleanly with version history. |
| **Limitations** | SQLAlchemy has a learning curve for async usage; Alembic migration scripts must be carefully reviewed before applying to production. |

### 3.5 Async Database Driver

| Technology | `asyncpg` |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Async PostgreSQL driver for use with FastAPI's async endpoints. |
| **Why suitable** | Fastest async PostgreSQL driver for Python. |
| **Alternatives** | `psycopg3` (also supports async; official PostgreSQL Python driver). |

---

## 4. Authentication

### 4.1 User Authentication

| Technology | JWT (JSON Web Tokens) via `python-jose` or `PyJWT` |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Authenticate mobile app users and laptop agents with the backend. |
| **Why suitable** | Stateless, widely supported, standard in API authentication. |
| **Limitations** | Token revocation requires a denylist or short expiry + refresh token pattern — must be implemented correctly. |

### 4.2 Device Authentication

| Technology | Per-device API token (opaque token or JWT) |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Authenticate the laptop agent with the backend as a specific registered device. |
| **Why suitable** | Simple to implement; separates device identity from user identity. |
| **Alternatives** | Mutual TLS (mTLS) for stronger device authentication (more complex). Decision pending. |

### 4.3 Password Hashing

| Technology | `bcrypt` via `passlib` |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Hash user passwords before storing them in the database. |
| **Why suitable** | Bcrypt is the standard for password hashing; `passlib` provides a clean Python interface. |

---

## 5. Mobile Application

### 5.1 Mobile Framework

| Technology | Flutter (Dart) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Build the Android mobile dashboard application. |
| **Why suitable** | Single codebase for Android (and iOS in future); rich UI component library; good performance; growing community; strong support for REST API integration. |
| **Alternatives considered** | React Native (JavaScript-based, large ecosystem but more fragile); Kotlin (native Android, best performance but Android-only, steeper learning curve for a cross-platform future). |
| **Limitations** | Dart is a less common language; Flutter app size is larger than native; some platform-specific features require native plugins. |

### 5.2 Mobile HTTP Client

| Technology | `dio` (Dart HTTP library) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Handle REST API calls from the Flutter mobile app to the backend. |
| **Why suitable** | Feature-rich, supports interceptors, request cancellation, and JSON serialization; widely used in Flutter apps. |

### 5.3 Push Notifications

| Technology | Firebase Cloud Messaging (FCM) |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Deliver push notifications from the backend to the Android mobile app when high-severity alerts are generated. |
| **Why suitable** | Free tier is sufficient for this project; official Android push notification service; well-supported by Flutter. |
| **Limitations** | Requires a Google Firebase project; introduces a dependency on Google services; FCM messages pass through Google servers (privacy consideration — only alert severity and device ID should be in the notification payload). |
| **Alternatives** | Polling (mobile app polls the backend periodically — simpler but less real-time); WebSocket (real-time but requires persistent connection management). |

### 5.4 Mobile Local State

| Technology | `flutter_secure_storage` + `shared_preferences` |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Store JWT tokens securely on device; cache last-known security status for offline display. |

---

## 6. API Communication

| Technology | REST over HTTPS (JSON payloads) |
|---|---|
| **Status** | ✅ SELECTED |
| **Role** | Communication protocol between agent and backend, and between mobile app and backend. |
| **Why suitable** | Simple, widely supported, easy to test, well-understood. |

| Technology | WebSockets |
|---|---|
| **Status** | ⚠️ PROPOSED — NOT FINAL |
| **Role** | Real-time event streaming from backend to mobile app (optional upgrade). |
| **Why suitable** | Provides real-time push from server to client without polling. |
| **Limitations** | Adds complexity to both server and mobile client; polling may be sufficient for MVP. Decision pending. |

---

## 7. Encryption / Security Libraries

| Technology | Role | Status |
|---|---|---|
| `cryptography` (Python) | Encrypt sensitive config values and credentials stored by the agent | ✅ SELECTED |
| TLS via `httpx` or `requests` | Ensure HTTPS in agent-to-backend communication | ✅ SELECTED |
| `httpx` (async HTTP client) | Agent HTTP communication to backend | ✅ SELECTED |
| OS Credential Manager | Store device token securely on the laptop | ⚠️ PROPOSED — NOT FINAL |

---

## 8. Development Tools

| Tool | Role | Status |
|---|---|---|
| `ruff` | Python linting and formatting | ✅ SELECTED |
| `black` | Python code formatting | ✅ SELECTED |
| `mypy` | Python static type checking | ✅ SELECTED |
| `pre-commit` | Git pre-commit hooks for lint/format enforcement | ✅ SELECTED |
| `pydantic` | Data validation and settings management | ✅ SELECTED |
| VS Code | Primary code editor | ✅ SELECTED |
| Android Studio | Flutter/Android development | ✅ SELECTED |
| Postman / Bruno | API testing during development | ✅ SELECTED |
| Docker + Docker Compose | Backend and database local development environment | ⚠️ PROPOSED — NOT FINAL |

---

## 9. Testing Tools

| Tool | Role | Status |
|---|---|---|
| `pytest` | Python unit and integration testing | ✅ SELECTED |
| `pytest-asyncio` | Async test support for FastAPI | ✅ SELECTED |
| `httpx` (test client) | FastAPI endpoint testing | ✅ SELECTED |
| `factory_boy` | Test data factories for database models | ⚠️ PROPOSED — NOT FINAL |
| Flutter test framework | Mobile widget and unit testing | ✅ SELECTED |
| `locust` | API load/performance testing | ⚠️ PROPOSED — NOT FINAL |

---

## 10. Deployment Tools

| Tool | Role | Status |
|---|---|---|
| Docker | Containerize backend and database | ⚠️ PROPOSED — NOT FINAL |
| Docker Compose | Orchestrate local and demo deployment | ⚠️ PROPOSED — NOT FINAL |
| Uvicorn | ASGI server for FastAPI | ✅ SELECTED |
| GitHub Actions | CI/CD pipeline for automated testing | ⚠️ PROPOSED — NOT FINAL |
| Railway / Render / Fly.io | Cloud hosting for hackathon demo backend | ⚠️ PROPOSED — NOT FINAL |

> **Deployment platform:** No cloud platform has been selected yet. The backend will be deployable as a containerized application; the specific platform will be chosen based on cost, ease of deployment, and free-tier availability.

---

## Technology Stack Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAPTOP SECURITY AGENT                        │
│  Language: Python 3.10+                                         │
│  Process Monitoring: psutil                                     │
│  File Monitoring: watchdog                                      │
│  Windows APIs: pywin32, winreg                                  │
│  Local DB: SQLite                                               │
│  HTTP Client: httpx (async)                                     │
│  Config: YAML + Pydantic                                        │
├─────────────────────────────────────────────────────────────────┤
│                    AI / ML ENGINE                               │
│  Framework: scikit-learn                                        │
│  MVP Model: Isolation Forest (anomaly detection)                │
│  Data Processing: pandas, numpy                                 │
│  Serialization: joblib                                          │
├─────────────────────────────────────────────────────────────────┤
│                    BACKEND / API                                 │
│  Language: Python 3.10+                                         │
│  Framework: FastAPI                                             │
│  Database: PostgreSQL 14+                                       │
│  ORM: SQLAlchemy 2.x + Alembic                                  │
│  Auth: JWT (python-jose) + bcrypt (passlib)                     │
│  Server: Uvicorn                                                │
├─────────────────────────────────────────────────────────────────┤
│                    MOBILE APP                                   │
│  Framework: Flutter (Dart)                                      │
│  HTTP: dio                                                      │
│  Push Notifications: FCM [PROPOSED]                             │
│  Local Storage: flutter_secure_storage [PROPOSED]               │
└─────────────────────────────────────────────────────────────────┘
```

---

*Document version: 1.0 | Last updated: 2026-09-16*

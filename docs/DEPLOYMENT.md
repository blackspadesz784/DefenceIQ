# Deployment — AI-Powered Personal Security Layer

---

## Overview

This document describes deployment across three environments:

1. **Local Development** — For individual developer setup
2. **Hackathon Demo** — For a working demo with a real backend
3. **Future Production** — Guidance for a real production deployment (not implemented in MVP)

---

## Part 1: Local Development

### 1.1 Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Agent and backend |
| PostgreSQL | 14+ | Backend database |
| Flutter | 3.x | Mobile development |
| Android Studio | Latest | Flutter/Android |
| Git | Latest | Version control |
| Docker (optional) | Latest | Containerized local setup |
| VS Code | Latest | Recommended editor |

---

### 1.2 Environment Setup — Backend

```bash
# Clone the repository
git clone <repo-url>
cd AI-Personal-Security-Layer

# Create Python virtual environment for backend
cd backend
python -m venv .venv
.venv\Scripts\activate  # Windows
# OR: source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env  # Windows
# OR: cp .env.example .env

# Edit .env with your local values
# Required variables (see .env.example for full list):
#   DATABASE_URL=postgresql://user:password@localhost:5432/security_layer_db
#   JWT_SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
#   JWT_ALGORITHM=HS256
#   ACCESS_TOKEN_EXPIRE_MINUTES=60
#   REFRESH_TOKEN_EXPIRE_DAYS=7
#   FCM_SERVER_KEY=<your Firebase server key>

# Set up PostgreSQL database
# (Assumes PostgreSQL is running locally)
createdb security_layer_db

# Run Alembic migrations
alembic upgrade head

# Start the backend development server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at: `http://localhost:8000`
Swagger UI (API docs): `http://localhost:8000/docs`

---

### 1.3 Environment Setup — Agent

```bash
# From repository root
cd agent
python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt

# Copy and edit agent config
copy config.example.yaml config.yaml

# Edit config.yaml:
#   backend_url: http://localhost:8000
#   monitoring.watched_directories: [...your paths...]
#   detection.risk_thresholds: (use defaults initially)
#   ai.model_path: ../ai/models/anomaly_model_v1.joblib

# Run the agent
python main.py
```

> **Note:** On the first run, the agent will prompt for user credentials or a device token (depending on implementation). Register a user account via the backend Swagger UI first.

---

### 1.4 Environment Setup — Mobile App

```bash
# From repository root
cd mobile

# Get Flutter dependencies
flutter pub get

# Ensure an Android emulator is running or a physical device is connected
flutter devices

# Run the app
flutter run

# The app will prompt for the backend URL on first run
# Use: http://10.0.2.2:8000 (Android emulator → host machine localhost)
# Or: http://<your-machine-ip>:8000 (physical device on same network)
```

---

### 1.5 Optional: Docker Compose Local Setup

For consistent local development without manually managing PostgreSQL:

```yaml
# docker-compose.yml (to be created in /backend)
version: "3.9"
services:
  db:
    image: postgres:14
    environment:
      POSTGRES_USER: dev_user
      POSTGRES_PASSWORD: dev_password
      POSTGRES_DB: security_layer_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    build: ./backend
    env_file: ./backend/.env
    ports:
      - "8000:8000"
    depends_on:
      - db

volumes:
  postgres_data:
```

```bash
# Start backend + database
docker compose up -d

# Run migrations
docker compose exec backend alembic upgrade head
```

> **Status:** `docker-compose.yml` is **PROPOSED — NOT FINAL** and will be created during Phase 12.

---

### 1.6 Environment Variables

All environment variables for the backend are documented in `backend/.env.example`:

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/db` |
| `JWT_SECRET_KEY` | JWT signing key (min 32 random bytes) | `a1b2c3...` (generated, never hardcoded) |
| `JWT_ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | `60` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | `7` |
| `FCM_SERVER_KEY` | Firebase Cloud Messaging server key | `AAAA...` |
| `BACKEND_HOST` | Host for the Uvicorn server | `0.0.0.0` |
| `BACKEND_PORT` | Port for the Uvicorn server | `8000` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated) | `""` (empty for MVP — no browser clients) |

> **Never commit `.env` to Git.** Only `.env.example` is committed.

---

## Part 2: Hackathon Demo Deployment

### 2.1 Architecture

For the hackathon demo, the backend is deployed to a cloud platform with a public URL. The mobile app and agent connect over the internet.

```
Laptop (agent) → public internet → Cloud backend → FCM → Android phone
Android phone → public internet → Cloud backend
```

### 2.2 Backend Deployment (Cloud)

**Recommended platforms:** Railway, Render, Fly.io (evaluated for free-tier availability at deployment time)

> **Platform: PROPOSED — NOT FINAL.** The specific cloud platform will be chosen in Phase 12.

**General steps:**

1. Create an account on the chosen platform.
2. Create a new service from the backend Docker image or GitHub repository.
3. Create a managed PostgreSQL database on the same platform.
4. Set all environment variables in the platform's secrets manager (do not use `.env` files on the server).
5. Run `alembic upgrade head` on the deployed instance (one-time step).
6. Verify the health endpoint: `GET https://<backend-url>/api/v1/health` returns 200.

### 2.3 Mobile App — Demo Build

```bash
cd mobile

# Update the backend URL constant to the deployed backend URL
# (In a config file or environment-aware constant, not hardcoded)

# Build the release APK
flutter build apk --release

# APK location: mobile/build/app/outputs/flutter-apk/app-release.apk
# Install on demo phone:
adb install build/app/outputs/flutter-apk/app-release.apk
```

### 2.4 Agent — Demo Installation

```bash
# On the demo laptop (Windows):

# 1. Clone the repository or copy the agent directory
# 2. Create the virtual environment and install dependencies
cd agent
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 3. Edit config.yaml:
#    backend_url: https://<deployed-backend-url>

# 4. Store device credentials securely during registration
# 5. Start the agent
python main.py

# Optional: Register as a Windows service for autostart
# (implementation TBD in DEVELOPMENT_PLAN.md Phase 1)
```

### 2.5 Demo Scenario

Recommended demo flow:

1. Show mobile app dashboard — device online, risk score ~10 (clean).
2. On the demo laptop, run a simulated suspicious command:
   ```powershell
   powershell.exe -encodedCommand SGVsbG8gV29ybGQ=
   ```
3. Show the risk score rising on the mobile dashboard.
4. Show the alert appearing in the Alerts screen.
5. Optionally receive a push notification on the phone.
6. Show the Event Detail screen with the alert context.

---

## Part 3: Future Production Deployment

> **This section describes intended future architecture. None of this is implemented in the MVP.**

### 3.1 Infrastructure

| Component | Recommended |
|---|---|
| Backend | Containerized (Docker); behind a reverse proxy (nginx or Traefik) |
| Database | Managed PostgreSQL (AWS RDS, Supabase, or equivalent) with automated backups |
| TLS | Let's Encrypt (automated certificate renewal) |
| Secrets | Cloud provider secrets manager (AWS Secrets Manager, GCP Secret Manager) |
| Monitoring | Application performance monitoring (Sentry, Datadog, or equivalent) |
| Logging | Centralized structured logging (Loki, CloudWatch, or equivalent) |

### 3.2 Security Hardening for Production

- TLS certificate pinning in the agent and mobile app.
- Database encrypted at rest (cloud provider encryption + application-level encryption for sensitive fields).
- All secrets rotatable without downtime.
- Regular dependency vulnerability scans.
- Intrusion detection on the backend host.
- Rate limiting enforced at the load balancer level in addition to application level.

### 3.3 Monitoring and Alerting (Backend)

- Health check endpoint monitored every 60 seconds.
- Alert if backend is unhealthy for > 2 minutes.
- Alert if database connection fails.
- Monitor API error rates and response latency.
- Log and alert on unusual patterns: spike in 401 errors (brute force), spike in event rate (potential agent compromise).

### 3.4 Rollback

- Keep N-1 Docker image available for rollback.
- Database migrations must be reversible (Alembic downgrade must be tested before each production migration).
- Rollback procedure: redeploy the previous Docker image; if DB schema changed, run `alembic downgrade -1`.

---

## Logging

### Agent Logs

- Location: `agent/logs/agent.log` (configurable).
- Format: Structured text with timestamp, level, module, message.
- Rotation: Rotate daily; keep 7 days of logs.
- What is logged: Startup, shutdown, monitoring events (at DEBUG), rule matches (at INFO), alerts (at WARNING/ERROR), sync events (at INFO).
- What is NOT logged: Raw command-line arguments at INFO level; passwords; device tokens.

### Backend Logs

- Format: JSON structured logging (compatible with log aggregation platforms).
- What is logged: Request method + path + status + duration; events received; errors with stack traces.
- What is NOT logged: Request body content; JWT tokens; passwords.

---

*Document version: 1.0 | Last updated: 2026-09-16*

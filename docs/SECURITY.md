# Security Design — AI-Powered Personal Security Layer

---

## Overview

This document defines the security design for the AI-Powered Personal Security Layer. The system monitors other systems for threats, which makes its own security posture especially important — a compromised security agent would be counterproductive.

> **Disclaimer:** No system is absolutely secure. This document defines security controls appropriate for the project's scope and threat model. See [THREAT_MODEL.md](THREAT_MODEL.md) for threat-specific analysis and [LIMITATIONS.md](LIMITATIONS.md) for acknowledged security gaps.

---

## 1. Authentication

### 1.1 User Authentication (Mobile ↔ Backend)

- Users authenticate with email + password.
- Passwords must be at least 12 characters.
- Passwords are hashed using **bcrypt** (cost factor ≥ 12) before storage. Plaintext passwords are never stored.
- On successful login, the backend issues:
  - **Access Token:** JWT, short-lived (60 minutes).
  - **Refresh Token:** JWT or opaque token, longer-lived (7 days), stored as a hash in the database.
- Refresh tokens are rotated on each use (refresh rotates the token, not just extends it).
- Refresh tokens can be explicitly revoked (logout).

### 1.2 Device Authentication (Agent ↔ Backend)

- On first registration, the user's JWT authenticates the device registration request.
- The backend issues a **Device Token** — a long-lived credential unique to the device.
- The device token is shown to the agent once and never stored in plaintext on the backend (only its hash is stored).
- The agent stores the device token securely using the OS credential manager (Windows Credential Manager for MVP).
- All subsequent agent communication uses the device token.
- Device tokens are separate from user JWTs — a compromised device token does not expose user credentials.

---

## 2. Authorization

- All API endpoints require authentication. There are no public read endpoints except `/health`.
- Users can only access data for their own devices.
- The backend validates that the `device_id` in each request belongs to the authenticated user (or is the authenticated device).
- Device tokens are scoped to a single device — a device token cannot be used to register another device or access user account settings.

---

## 3. API Security

### 3.1 Transport Security

- All API communication uses **TLS 1.2 or higher**. No plaintext HTTP fallback.
- Certificate validation is enforced by the agent's HTTP client (`httpx`) and the mobile app.
- Self-signed certificates are not accepted in production. Development environments may use a local CA with explicit configuration.

### 3.2 Input Validation

- All API request bodies are validated using **Pydantic** schemas before processing.
- Unexpected or oversized fields are rejected with `400 VALIDATION_ERROR`.
- JSON payload size is limited server-side to prevent excessively large uploads (configurable, default: 1 MB per request, 5 MB for batch).
- String fields have explicit maximum lengths enforced by Pydantic.
- JSONB feature payload is validated against a known schema before storage.

### 3.3 Rate Limiting

- Auth endpoints (login, register): **10 requests/minute per IP**.
- Event submission: **100 requests/minute per device token**.
- Mobile dashboard reads: **60 requests/minute per user**.
- Batch sync: **10 requests/minute per device**.
- Rate limiting is enforced by the API layer. Responses: `429 RATE_LIMITED`.

### 3.4 SQL Injection Prevention

- All database queries use SQLAlchemy ORM with parameterized queries. Raw SQL is avoided.
- JSONB fields are never used to construct dynamic queries.

### 3.5 CORS Policy

- The backend API does not serve browser clients in the MVP (agent and mobile app only).
- CORS is configured to restrict origins. If a web dashboard is added in the future, an explicit allowlist of origins must be configured.

---

## 4. Secrets Management

| Secret | Where stored | Protection |
|---|---|---|
| User passwords | PostgreSQL `users.password_hash` | bcrypt hashed (cost ≥ 12) |
| JWT signing key | Backend environment variable | Never hardcoded; loaded from `.env` at startup |
| Device token | Agent: OS Credential Manager (Windows) | OS-protected credential storage |
| Device token hash | Backend: PostgreSQL | Only hash stored; original not recoverable |
| Database connection string | Backend environment variable | Never committed to Git |
| FCM service key | Backend environment variable | Never committed to Git |
| API keys (future) | Environment variables | Never committed to Git |

**`.env` files are gitignored.** Only `.env.example` templates are committed to the repository.

---

## 5. Encryption in Transit

All communication channels use TLS:

| Path | Protocol |
|---|---|
| Agent → Backend | HTTPS (TLS 1.2+) via `httpx` |
| Mobile App → Backend | HTTPS (TLS 1.2+) via `dio` |
| Backend → FCM | HTTPS (Google-managed) |

There is no plaintext fallback for any of these connections.

---

## 6. Encryption at Rest

| Data | MVP Status | Recommendation |
|---|---|---|
| PostgreSQL database | Not encrypted at database level in MVP | Use disk-level encryption (OS/cloud-provided) in production |
| SQLite local database | Not encrypted in MVP | Phase 2: use SQLCipher or encrypted file system |
| Agent config file | Not encrypted in MVP | Store sensitive values in OS Credential Manager instead of config YAML |
| Serialized ML model | Not encrypted | Low sensitivity; not a security concern |

> **MVP Note:** Encryption at rest is not implemented at the application level for MVP. It is expected that the development machine uses full-disk encryption (e.g., BitLocker on Windows, FileVault on macOS) as a compensating control.

---

## 7. Least Privilege

### Agent Permissions

The agent runs with the minimum permissions required:

| Permission | Reason | Minimum required? |
|---|---|---|
| Read process list | Process monitoring | ✅ |
| Read process command-line arguments | Script detection | ✅ |
| Read file system events | File monitoring | ✅ |
| Read network connection table | Network monitoring | ✅ |
| Read Windows Registry (Run keys) | Persistence monitoring | ✅ |
| Write to local SQLite file | Event storage | ✅ |
| Outbound HTTPS | Backend communication | ✅ |
| Kill processes | Response engine | ❌ Not in MVP; requires elevated permission |
| Write to Registry | Not required | ❌ Denied |
| Install services | Autostart | Requires admin only at install time; agent runtime does not need it |

The agent does **not** require kernel-level drivers. All monitoring is from userspace APIs.

### Backend Process Permissions

- The FastAPI server runs as a non-root user.
- Database credentials are scoped to the specific database, not the full PostgreSQL instance.
- The backend process has no file system write access beyond its working directory and log directory.

---

## 8. Secure Logging

| Rule | Detail |
|---|---|
| No credentials in logs | JWT tokens, passwords, and device tokens must never be written to log files |
| No sensitive feature data in logs | Command-line arguments are logged at DEBUG level only, never at INFO/WARNING |
| Log injection prevention | Log messages containing user-supplied data are sanitized for newline characters |
| Log access control | Log files are written with restricted permissions (readable only by the agent user) |
| Agent operational logs | Stored in a dedicated file, separate from security event data |
| Backend access logs | Include request method, path, status code, response time — no request body content |

---

## 9. Token Security

| Concern | Mitigation |
|---|---|
| JWT expiry | Access tokens expire in 60 minutes; short window limits exposure if stolen |
| JWT signing | HS256 (HMAC-SHA256) with a strong random secret (≥ 256 bits); RSA considered for Phase 2 |
| JWT claims | Include `user_id`, `device_id` (device tokens), `exp`, `iat`, `jti` |
| Token revocation | Refresh tokens stored as hashes; can be revoked by deleting the DB record |
| Token leakage | HTTPS enforced; tokens not included in URL query parameters |
| Mobile token storage | `flutter_secure_storage` uses the Android Keystore (hardware-backed on supported devices) |

---

## 10. Agent Protection

The agent is itself a target — an attacker who disables the agent eliminates the security monitoring layer.

| Threat | Mitigation |
|---|---|
| Agent process killed | OS service manager restarts the agent automatically |
| Agent files deleted | Service manager triggers restart; agent re-initializes from config |
| Agent config tampered | Config hash is verified at startup; invalid config triggers a warning and uses defaults |
| Agent binary replaced | Code signing of the agent binary (future); currently not implemented in MVP |
| Agent credentials stolen | OS Credential Manager protects device token; credential rotation supported |

> **Note:** A sufficiently privileged attacker with local access can disable the agent. This is an inherent limitation of any userspace security tool. See [LIMITATIONS.md](LIMITATIONS.md).

---

## 11. Handling of Suspicious Files

The agent may encounter suspicious files during monitoring. Rules for safe handling:

- **No execution of suspicious files** — the agent reads file metadata and computes hashes only; it never executes detected files.
- **SHA-256 hashing only** — file hash computation reads the file stream without interpreting content.
- **No content transmission** — file content is never sent to the backend. Only the hash, path, and metadata are transmitted.
- **Quarantine (future):** When implemented, quarantine moves the file to an isolated directory with restricted permissions. The original location is restored on rollback.

---

## 12. Controlled Response Limitations

Automated defensive actions carry real risk:

| Risk | Mitigation |
|---|---|
| False positive → legitimate process killed | MVP does not auto-kill processes; only logs and flags |
| False positive → legitimate file quarantined | Quarantine not implemented in MVP |
| Response action exploited to cause DoS | All actions require authentication and are logged |
| User-initiated action via compromised mobile app | Action requests are validated against device ownership before execution |

**MVP response posture:** Conservative. The agent logs, scores, and alerts. It does not take automated destructive actions. All destructive actions (Phase 2+) require explicit user confirmation.

---

## 13. Tamper Resistance

| Control | Status |
|---|---|
| Agent binary integrity verification | ❌ Not implemented in MVP |
| Configuration file integrity check | ⚠️ Hash verification at startup (proposed) |
| Local database integrity check | ❌ Not implemented in MVP |
| Backend audit log | ✅ All API mutations are logged |
| Alert manipulation detection | ❌ Not implemented in MVP |

Tamper resistance is a significant area for improvement in Phase 2. See [THREAT_MODEL.md](THREAT_MODEL.md) for agent tamper threat scenarios.

---

*Document version: 1.0 | Last updated: 2026-09-16*

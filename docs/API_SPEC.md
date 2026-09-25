# API Specification — AI-Powered Personal Security Layer

---

## Overview

This document defines the API contract for the backend REST API. It is a design document only — **no implementation exists yet.**

All endpoints use:
- **Base URL:** `https://<backend-host>/api/v1`
- **Format:** JSON request and response bodies
- **Authentication:** JWT Bearer token in the `Authorization` header
- **TLS:** All traffic over HTTPS (TLS 1.2+)

---

## Authentication Scheme

### User Authentication
```
Authorization: Bearer <user_jwt_token>
```

### Device Authentication
```
Authorization: Bearer <device_token>
X-Device-ID: <device_id>
```

---

## Error Response Format

All error responses follow a consistent structure:

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication token is expired or invalid.",
    "request_id": "req_abc123"
  }
}
```

**Standard error codes:**

| HTTP Status | Code | Meaning |
|---|---|---|
| 400 | VALIDATION_ERROR | Request body failed validation |
| 401 | UNAUTHORIZED | Missing or invalid token |
| 403 | FORBIDDEN | Authenticated but insufficient permissions |
| 404 | NOT_FOUND | Resource does not exist |
| 409 | CONFLICT | Resource already exists |
| 422 | UNPROCESSABLE_ENTITY | Semantic validation error |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server-side error |
| 503 | SERVICE_UNAVAILABLE | Database or upstream failure |

---

## 1. Authentication Endpoints

### POST /auth/register

Register a new user account.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | None |

**Request:**
```json
{
  "email": "user@example.com",
  "password": "MinLength12CharPass!",
  "display_name": "Alice"
}
```

**Response 201:**
```json
{
  "user_id": "usr_7a2b3c",
  "email": "user@example.com",
  "display_name": "Alice",
  "created_at": "2026-09-16T08:00:00Z"
}
```

**Error responses:** `400 VALIDATION_ERROR`, `409 CONFLICT` (email already registered)

---

### POST /auth/login

Authenticate a user and receive a JWT.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | None |

**Request:**
```json
{
  "email": "user@example.com",
  "password": "MinLength12CharPass!"
}
```

**Response 200:**
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Error responses:** `401 UNAUTHORIZED` (invalid credentials), `429 RATE_LIMITED`

---

### POST /auth/refresh

Refresh an expired access token using a refresh token.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | None (refresh token in body) |

**Request:**
```json
{
  "refresh_token": "eyJhbGci..."
}
```

**Response 200:**
```json
{
  "access_token": "eyJhbGci...",
  "expires_in": 3600
}
```

**Error responses:** `401 UNAUTHORIZED` (invalid/expired refresh token)

---

### POST /auth/logout

Invalidate the current session.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | User JWT |

**Request:** Empty body

**Response 204:** No content

---

## 2. Device Registration Endpoints

### POST /devices/register

Register a laptop device with the user account. Called by the agent on first run.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | User JWT |

**Request:**
```json
{
  "hostname": "DESKTOP-ABC123",
  "os": "Windows 11",
  "os_version": "23H2",
  "agent_version": "0.1.0",
  "display_name": "Work Laptop"
}
```

**Response 201:**
```json
{
  "device_id": "dev_9x8y7z",
  "device_token": "dt_eyJhbGci...",
  "display_name": "Work Laptop",
  "registered_at": "2026-09-16T08:01:00Z"
}
```

The `device_token` is used for all subsequent agent → backend communication.

**Error responses:** `401 UNAUTHORIZED`, `409 CONFLICT` (device already registered)

---

### GET /devices

List all devices registered to the authenticated user.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |

**Response 200:**
```json
{
  "devices": [
    {
      "device_id": "dev_9x8y7z",
      "display_name": "Work Laptop",
      "hostname": "DESKTOP-ABC123",
      "os": "Windows 11",
      "agent_version": "0.1.0",
      "status": "ONLINE",
      "last_seen": "2026-09-16T13:45:00Z",
      "current_risk_score": 42,
      "current_severity": "MEDIUM"
    }
  ]
}
```

---

### GET /devices/{device_id}

Get detailed status for a specific device.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |
| **Path param** | `device_id` |

**Response 200:**
```json
{
  "device_id": "dev_9x8y7z",
  "display_name": "Work Laptop",
  "hostname": "DESKTOP-ABC123",
  "os": "Windows 11",
  "os_version": "23H2",
  "agent_version": "0.1.0",
  "status": "ONLINE",
  "last_seen": "2026-09-16T13:45:00Z",
  "registered_at": "2026-09-16T08:01:00Z",
  "current_risk_score": 42,
  "current_severity": "MEDIUM",
  "active_alerts_count": 2
}
```

**Error responses:** `404 NOT_FOUND`, `403 FORBIDDEN`

---

### POST /devices/{device_id}/heartbeat

Agent sends a periodic heartbeat to signal it is running.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | Device token |

**Request:**
```json
{
  "current_risk_score": 42,
  "agent_version": "0.1.0",
  "uptime_seconds": 3600
}
```

**Response 200:**
```json
{
  "acknowledged": true,
  "server_time": "2026-09-16T13:45:01Z"
}
```

---

## 3. Security Event Endpoints

### POST /events

Submit a single security event from the agent.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | Device token |

**Request:**
```json
{
  "event_id": "evt_20260916_001",
  "event_type": "PROCESS_CREATION",
  "timestamp": "2026-09-16T08:12:30Z",
  "severity": "HIGH",
  "rule_ids": ["SCRIPT-001"],
  "ai_anomaly_score": 0.72,
  "risk_score_at_event": 67,
  "features": {
    "process_name": "powershell.exe",
    "has_encoded_args": true,
    "is_in_temp_directory": false,
    "parent_process_type": "OFFICE_APP",
    "path_legitimacy_score": 0.9
  },
  "description": "PowerShell executed with encoded command argument from parent process: winword.exe",
  "offline": false
}
```

**Response 201:**
```json
{
  "event_id": "evt_20260916_001",
  "stored": true
}
```

**Error responses:** `400 VALIDATION_ERROR`, `401 UNAUTHORIZED`, `409 CONFLICT` (duplicate event_id)

---

### POST /events/batch

Submit multiple queued events (used during offline sync).

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | Device token |

**Request:**
```json
{
  "events": [
    { "event_id": "evt_20260916_001", "..." },
    { "event_id": "evt_20260916_002", "..." }
  ]
}
```

**Response 200:**
```json
{
  "received": 2,
  "stored": 2,
  "duplicates_skipped": 0,
  "errors": []
}
```

---

### GET /events

Retrieve security events for a device (mobile dashboard consumption).

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |
| **Query params** | `device_id`, `severity` (optional), `limit` (default 50), `offset` (default 0), `from_date`, `to_date` |

**Response 200:**
```json
{
  "total": 142,
  "limit": 50,
  "offset": 0,
  "events": [
    {
      "event_id": "evt_20260916_001",
      "event_type": "PROCESS_CREATION",
      "timestamp": "2026-09-16T08:12:30Z",
      "severity": "HIGH",
      "description": "PowerShell executed with encoded command argument from parent process: winword.exe",
      "rule_ids": ["SCRIPT-001"],
      "ai_anomaly_score": 0.72,
      "risk_score_at_event": 67
    }
  ]
}
```

---

### GET /events/{event_id}

Get full detail for a specific security event.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |

**Response 200:**
```json
{
  "event_id": "evt_20260916_001",
  "device_id": "dev_9x8y7z",
  "event_type": "PROCESS_CREATION",
  "timestamp": "2026-09-16T08:12:30Z",
  "severity": "HIGH",
  "description": "PowerShell executed with encoded command argument from parent process: winword.exe",
  "rule_ids": ["SCRIPT-001"],
  "ai_anomaly_score": 0.72,
  "risk_score_at_event": 67,
  "features": {
    "process_name": "powershell.exe",
    "has_encoded_args": true,
    "parent_process_type": "OFFICE_APP",
    "path_legitimacy_score": 0.9
  },
  "offline": false,
  "received_at": "2026-09-16T08:12:35Z"
}
```

---

## 4. Alert Endpoints

### GET /alerts

List alerts for a device.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |
| **Query params** | `device_id`, `severity` (optional), `status` (optional: ACTIVE/ACKNOWLEDGED), `limit`, `offset` |

**Response 200:**
```json
{
  "total": 3,
  "alerts": [
    {
      "alert_id": "alt_20260916_001",
      "device_id": "dev_9x8y7z",
      "severity": "HIGH",
      "status": "ACTIVE",
      "title": "PowerShell Encoded Command Execution Detected",
      "description": "PowerShell was executed with an encoded command from a Microsoft Office parent process.",
      "triggered_at": "2026-09-16T08:12:30Z",
      "risk_score_at_alert": 67,
      "triggering_event_ids": ["evt_20260916_001"]
    }
  ]
}
```

---

### GET /alerts/{alert_id}

Get full details for a specific alert.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |

**Response 200:** Full alert object including triggering events and rule matches.

---

### PATCH /alerts/{alert_id}/acknowledge

Acknowledge an alert (Phase 2).

| Field | Value |
|---|---|
| **Method** | PATCH |
| **Auth** | User JWT |

**Request:**
```json
{
  "note": "Reviewed — confirmed false positive. Was a legitimate script."
}
```

**Response 200:**
```json
{
  "alert_id": "alt_20260916_001",
  "status": "ACKNOWLEDGED",
  "acknowledged_at": "2026-09-16T09:00:00Z"
}
```

---

## 5. Risk Score Endpoints

### GET /risk-score

Get the current risk score for a device.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |
| **Query params** | `device_id` |

**Response 200:**
```json
{
  "device_id": "dev_9x8y7z",
  "current_score": 42,
  "severity": "MEDIUM",
  "last_updated": "2026-09-16T13:44:00Z"
}
```

---

### GET /risk-score/history

Get risk score history for trend chart.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |
| **Query params** | `device_id`, `period` (e.g., `7d`, `24h`, `30d`) |

**Response 200:**
```json
{
  "device_id": "dev_9x8y7z",
  "period": "7d",
  "data_points": [
    { "timestamp": "2026-09-10T00:00:00Z", "score": 10, "severity": "LOW" },
    { "timestamp": "2026-09-11T00:00:00Z", "score": 15, "severity": "LOW" },
    { "timestamp": "2026-09-16T00:00:00Z", "score": 42, "severity": "MEDIUM" }
  ]
}
```

---

### POST /risk-scores/batch

Submit risk score history during offline sync.

| Field | Value |
|---|---|
| **Method** | POST |
| **Auth** | Device token |

**Request:**
```json
{
  "scores": [
    { "timestamp": "2026-09-15T10:00:00Z", "score": 20 },
    { "timestamp": "2026-09-15T11:00:00Z", "score": 35 }
  ]
}
```

**Response 200:** `{ "stored": 2 }`

---

## 6. Sync Endpoint

### GET /sync/state

Check the last received event for a device (used during offline sync initialization).

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | Device token |
| **Query params** | `device_id` |

**Response 200:**
```json
{
  "device_id": "dev_9x8y7z",
  "last_received_event_id": "evt_20260915_0045",
  "last_received_at": "2026-09-15T17:30:00Z"
}
```

---

## 7. Response Action Endpoints

### GET /actions

List response actions taken for a device.

| Field | Value |
|---|---|
| **Method** | GET |
| **Auth** | User JWT |
| **Query params** | `device_id`, `limit`, `offset` |

**Response 200:**
```json
{
  "actions": [
    {
      "action_id": "act_001",
      "device_id": "dev_9x8y7z",
      "action_type": "PROCESS_FLAGGED",
      "target": "PID 4512 (powershell.exe)",
      "initiated_by": "AGENT_AUTO",
      "timestamp": "2026-09-16T08:12:45Z",
      "status": "COMPLETED",
      "note": "Process flagged for user review"
    }
  ]
}
```

---

## 8. Health Check

### GET /health

Backend health check. No authentication required.

**Response 200:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "database": "connected",
  "timestamp": "2026-09-16T13:54:00Z"
}
```

**Response 503:**
```json
{
  "status": "degraded",
  "database": "unreachable",
  "timestamp": "2026-09-16T13:54:00Z"
}
```

---

## API Rate Limits

| Endpoint Category | Rate Limit |
|---|---|
| Auth (login, register) | 10 requests / minute per IP |
| Agent event submission | 100 requests / minute per device |
| Agent heartbeat | 2 requests / minute per device |
| Mobile dashboard reads | 60 requests / minute per user |
| Batch event sync | 10 requests / minute per device |

---

*Document version: 1.0 | Last updated: 2026-09-16 — API contract only, not implemented*

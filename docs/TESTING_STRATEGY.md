# Testing Strategy — AI-Powered Personal Security Layer

---

## Overview

This document defines the testing approach for all components of the AI-Powered Personal Security Layer. Tests are organized by category. Each category has defined scope, tools, and example scenarios.

**Primary testing framework:** `pytest` (Python); Flutter test framework (mobile).

---

## 1. Unit Testing

Unit tests validate individual functions and classes in isolation, using mocked dependencies.

### 1.1 Agent Unit Tests

**Scope:** Each monitor, feature extractor, rule engine, risk scorer, alert manager in isolation.

**Tool:** `pytest` with mocked psutil, watchdog, winreg responses.

**Location:** `agent/tests/`

**Example test scenarios:**

```python
# Test: Process monitor produces correctly structured event
def test_process_monitor_creates_event():
    mock_process = MockProcess(pid=1234, name="powershell.exe", ppid=500)
    monitor = ProcessMonitor(config=test_config)
    event = monitor._build_event(mock_process)
    assert event["pid"] == 1234
    assert event["name"] == "powershell.exe"
    assert "timestamp" in event

# Test: Feature extractor correctly sets has_encoded_args
def test_feature_extractor_encoded_args():
    raw_event = {"process_name": "powershell.exe", "cmdline": "-enc SGVsbG8="}
    features = FeatureExtractor().extract(raw_event)
    assert features["has_encoded_args"] is True

# Test: Rule engine fires SCRIPT-001 for encoded PowerShell
def test_rule_engine_script_001():
    features = {"process_name": "powershell.exe", "has_encoded_args": True}
    results = RuleEngine(rules_dir="detection/rules").evaluate(features)
    assert any(r["rule_id"] == "SCRIPT-001" for r in results)

# Test: Rule engine does not fire for normal PowerShell invocation
def test_rule_engine_no_false_positive_normal_ps():
    features = {"process_name": "powershell.exe", "has_encoded_args": False,
                "has_download_cradle": False, "has_bypass_flags": False}
    results = RuleEngine(rules_dir="detection/rules").evaluate(features)
    assert len([r for r in results if r["severity"] in ["HIGH", "CRITICAL"]]) == 0

# Test: Risk scorer produces correct composite score
def test_risk_scorer_weighted_combination():
    scorer = RiskScorer()
    score = scorer.compute(rule_matches=[{"score_contribution": 30, "severity": "HIGH"}],
                           ai_score=0.5)
    assert 40 <= score <= 60  # Expected range
```

### 1.2 Backend Unit Tests

**Scope:** Each API endpoint, service function, auth handler.

**Tool:** `pytest` with `httpx.AsyncClient` and a test PostgreSQL database.

**Location:** `backend/tests/`

**Example test scenarios:**

```python
# Test: Login with correct credentials returns JWT
async def test_login_success():
    response = await client.post("/api/v1/auth/login", json={"email": "test@test.com", "password": "TestPass123!"})
    assert response.status_code == 200
    assert "access_token" in response.json()

# Test: Login with wrong password returns 401
async def test_login_wrong_password():
    response = await client.post("/api/v1/auth/login", json={"email": "test@test.com", "password": "wrong"})
    assert response.status_code == 401

# Test: Event submission stores event in database
async def test_event_submission():
    response = await device_client.post("/api/v1/events", json=sample_event)
    assert response.status_code == 201
    # Verify it appears in GET /events
    get_response = await user_client.get(f"/api/v1/events?device_id={DEVICE_ID}")
    assert any(e["event_id"] == sample_event["event_id"] for e in get_response.json()["events"])

# Test: Duplicate event_id is rejected with 409
async def test_duplicate_event_rejected():
    await device_client.post("/api/v1/events", json=sample_event)
    response = await device_client.post("/api/v1/events", json=sample_event)
    assert response.status_code == 409
```

---

## 2. Integration Testing

Integration tests validate the interaction between components — agent ↔ backend, backend ↔ database.

**Tool:** `pytest` against a real test backend and test PostgreSQL instance (not production).

**Location:** `tests/integration/`

### 2.1 Agent ↔ Backend Integration Tests

| Test | Description |
|---|---|
| `test_agent_sends_event.py` | Agent sends an event; verify it appears in the backend database |
| `test_heartbeat_updates_status.py` | Agent sends heartbeat; verify `devices.last_seen` is updated |
| `test_batch_sync.py` | Agent sends batch of queued events; verify all are stored with correct event_ids |
| `test_device_registration.py` | Agent registers a new device; verify device record created in DB |

### 2.2 Backend ↔ Database Integration Tests

| Test | Description |
|---|---|
| `test_event_storage.py` | Event stored and retrieved correctly from PostgreSQL |
| `test_risk_score_history.py` | Multiple risk scores stored and returned in correct order |
| `test_alert_deduplication_db.py` | Duplicate event IDs from the same device are not stored twice |

---

## 3. Agent-Specific Testing

### 3.1 Monitor Testing on Windows

Monitors must be tested on a real Windows system because they use Windows-specific APIs.

| Test | Method |
|---|---|
| Process Monitor — captures new process | Start a known test process; verify it appears in monitor output |
| File Monitor — detects file creation | Create a test file in a monitored directory; verify event generated |
| Network Monitor — detects new connection | Open a test TCP connection; verify it appears in monitor output |
| Startup Monitor — detects Registry change | Add a test Registry Run key; verify event generated; clean up |
| Command Monitor — detects PowerShell invocation | Run `powershell.exe -command "Write-Host test"`; verify event captured |

**Important:** Run-key and Registry tests must clean up after themselves to avoid leaving test artifacts.

---

## 4. Detection Testing

Detection tests verify that the detection pipeline produces the correct output for known inputs.

### 4.1 Rule Detection Tests

Each rule must have a test that:
1. Provides a feature vector designed to trigger the rule.
2. Asserts that the rule fires.
3. Asserts that the score contribution is correct.

And a complementary test that:
1. Provides a benign feature vector.
2. Asserts the rule does NOT fire.

**Example detection scenarios (all simulated — no real malware):**

| Scenario | Feature Vector | Expected Rule | Expected Severity |
|---|---|---|---|
| PowerShell encoded command | `process_name="powershell.exe"`, `has_encoded_args=True` | SCRIPT-001 | HIGH |
| Office spawning CMD | `process_name="cmd.exe"`, `parent_process_type="OFFICE_APP"` | PROC-002 | HIGH |
| Mass file modification | `file_modification_rate=75` | FILE-001 | HIGH |
| New Registry Run key to temp | `new_run_key=True`, `run_key_in_temp=True` | PERS-002 | CRITICAL |
| Unsigned process on unusual port | `is_signed_binary=False`, `connects_on_unusual_port=True` | NET-001 | MEDIUM |

### 4.2 Risk Score Scenarios

| Scenario | Input signals | Expected risk score range |
|---|---|---|
| Idle clean system | No rule matches, AI score 0.1 | 0–15 |
| Single medium-severity rule match | One MEDIUM rule, AI score 0.3 | 15–35 |
| Multiple high-severity matches | Two HIGH rules, AI score 0.6 | 55–75 |
| Critical pattern | CRITICAL rule + HIGH rule + AI score 0.8 | 85–100 |

---

## 5. AI Model Testing

### 5.1 Model Loading Test

```python
def test_model_loads_correctly():
    engine = AIEngine(model_path="ai/models/anomaly_model_v1.joblib")
    assert engine.is_ready()

def test_model_scores_normal_behavior_low():
    engine = AIEngine(model_path="ai/models/anomaly_model_v1.joblib")
    normal_features = generate_normal_feature_vector()
    score = engine.score(normal_features)
    assert score < 0.5  # Normal behavior should score low

def test_model_scores_extreme_behavior_high():
    engine = AIEngine(model_path="ai/models/anomaly_model_v1.joblib")
    extreme_features = generate_extreme_feature_vector()  # All features at maximum
    score = engine.score(extreme_features)
    assert score > 0.6

def test_model_fallback_on_missing_file():
    engine = AIEngine(model_path="nonexistent.joblib")
    assert not engine.is_ready()
    # Agent should continue without AI scoring
    assert engine.score({}) == 0.0  # Safe default
```

### 5.2 False Positive Rate Evaluation

After training, evaluate on a held-out benign dataset:

```
Target: < 10% false positive rate on normal behavior
```

This evaluation is documented in `ai/experiments/experiment_log.md` and is not an automated unit test but a training evaluation step.

---

## 6. API Testing

### 6.1 Automated API Tests

All endpoints in [API_SPEC.md](API_SPEC.md) must have at minimum:

- A test for the happy path (expected 2xx response).
- A test for authentication failure (401).
- A test for validation failure (400/422).
- A test for not-found (404) where applicable.

**Tool:** `pytest` + `httpx.AsyncClient` pointed at a test backend instance.

### 6.2 Manual API Testing

During development, use Postman or Bruno to:

- Import the API collection.
- Run all endpoints against the local dev server.
- Verify response formats match `API_SPEC.md`.

---

## 7. Database Testing

| Test | Description |
|---|---|
| Schema migration test | Run all Alembic migrations on a clean database; verify all tables exist with correct columns |
| Index existence test | Verify all defined indexes exist after migration |
| Retention test | Simulate retention cleanup job; verify old records are deleted and new records are preserved |
| Cascade delete test | Delete a user; verify all associated device, event, alert, and score records are deleted |

---

## 8. Mobile Testing

**Tool:** Flutter test framework (`flutter test`).

### 8.1 Widget Tests

| Test | Description |
|---|---|
| Login screen renders correctly | Login screen displays email/password fields and submit button |
| Dashboard shows risk score | Given a mock API response, dashboard displays the correct risk score |
| Alert card renders severity | Alert card displays the correct severity color and badge |
| History chart renders | Given mock score history, the chart renders without errors |

### 8.2 Integration Tests (Mobile ↔ Backend)

- Verify the mobile app successfully authenticates against the backend.
- Verify the dashboard screen displays data from the backend.
- Verify push notifications are received when a High-severity alert is created.

---

## 9. End-to-End Testing

End-to-end tests simulate the full pipeline from a suspicious event on the laptop to the mobile dashboard.

**Location:** `tests/e2e/`

### E2E Scenario 1: Normal Alert Flow

```
1. Start agent on test Windows system
2. Trigger a simulated suspicious event:
   - Create a test PowerShell process with -enc argument
3. Assert: Agent generates an alert within 10 seconds
4. Assert: Alert appears in local SQLite
5. Assert: Alert transmitted to backend within 30 seconds
6. Assert: Alert appears in GET /alerts response from backend
7. Assert: Push notification received on mobile device (manual verification)
```

### E2E Scenario 2: Offline Mode and Sync

```
1. Start agent on test Windows system
2. Disconnect agent from internet (firewall rule or proxy)
3. Trigger 10 simulated security events over 2 minutes
4. Assert: Events stored in offline_queue in SQLite
5. Assert: Risk score still updated locally
6. Restore internet connection
7. Assert: All 10 events appear in backend within 60 seconds
8. Assert: Events have original timestamps (not the sync time)
9. Assert: offline_queue is empty after sync
```

---

## 10. Performance Testing

**Tool:** `locust` (backend); `psutil`-based agent resource measurement.

### Agent Performance Tests

| Metric | Test | Target |
|---|---|---|
| CPU usage (idle) | Run agent for 30 min on idle Windows system; measure CPU% | < 2% average |
| CPU usage (active detection) | Trigger many file events simultaneously; measure CPU% | < 10% peak |
| RAM usage | Run agent for 1 hour; measure RSS memory | < 150 MB |
| AI inference time | Time 1,000 consecutive `engine.score()` calls | < 100 ms each |

### Backend Performance Tests

| Metric | Test | Target |
|---|---|---|
| Event submission throughput | 100 concurrent event POST requests | All succeed in < 2 seconds |
| Dashboard read latency | 60 concurrent GET /events requests | < 500 ms p99 |

---

## 11. Security Testing

| Test | Description |
|---|---|
| Unauthenticated access | All endpoints must return 401 with no or invalid token |
| SQL injection attempt | Send SQL metacharacters in event payload; verify no DB error |
| Oversized payload | Send a 10 MB POST body; verify 400/413 response |
| Expired JWT | Use an expired JWT; verify 401 response |
| Rate limiting | Send 200 login requests in 1 minute from the same IP; verify 429 after limit |
| Secrets in responses | Verify no password hashes or token values are returned in any response |

---

## 12. False Positive Testing

A separate test suite specifically for verifying that legitimate, common system behaviors do NOT trigger false positive alerts.

| Scenario | Expected outcome |
|---|---|
| OneDrive/Dropbox sync creating many files | File modification rate rule does NOT fire (excluded path or rate below threshold) |
| Python script run by developer | Does not trigger SCRIPT-001 (no encoded args) |
| Browser making network connections | Network monitor does not flag standard browser behavior |
| Normal PowerShell profile load | `powershell.exe -noprofile` alone does NOT trigger alert (missing corroborating signals) |
| Software installer running from Downloads | Flagged for review but does NOT reach Critical severity without additional signals |

---

## 13. False Negative Testing

False negative testing acknowledges the system's limitations and documents known gaps.

| Scenario | Expected detection outcome | Note |
|---|---|---|
| Sophisticated fileless malware | May not be detected | Documented limitation |
| Process mimicking a trusted binary name | Partially detected (path legitimacy check, not name alone) | |
| Slow, low-volume attack operating below behavioral thresholds | May not be detected | Documented limitation |
| Attacker who disables the agent before acting | Not detected | Tamper resistance gap |

These scenarios are documented in [LIMITATIONS.md](LIMITATIONS.md) and are not expected to be detected in the MVP.

---

*Document version: 1.0 | Last updated: 2026-09-16*

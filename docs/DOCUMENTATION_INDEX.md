# Documentation Index — AI-Powered Personal Security Layer

---

## Overview

This is the master index for all project documentation. It includes the purpose of each document, the recommended reading order, and cross-document dependencies.

All documentation files are located in the `/docs` folder. The repository root contains only `README.md`.

---

## Document Index

| # | File | Purpose |
|---|---|---|
| 1 | [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | Project concept, problem statement, goals, use cases, scope, and MVP definition |
| 2 | [REQUIREMENTS.md](REQUIREMENTS.md) | Complete functional, non-functional, hardware, software, and operational requirements |
| 3 | [TECH_STACK.md](TECH_STACK.md) | Technology selection for all components with rationale, alternatives, and limitations |
| 4 | [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, component design, data flow, offline operation, and Mermaid diagrams |
| 5 | [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | Repository directory structure with purpose of every major directory and file |
| 6 | [FEATURES.md](FEATURES.md) | Feature list organized by MVP, Phase 2, and future tiers |
| 7 | [DETECTION_LOGIC.md](DETECTION_LOGIC.md) | Detection pipeline specification: rules, AI scoring, risk scoring, false positives/negatives |
| 8 | [AI_MODEL.md](AI_MODEL.md) | AI/ML model approach, training pipeline, evaluation, inference, versioning, limitations |
| 9 | [DATA_FLOW.md](DATA_FLOW.md) | End-to-end data flow with Mermaid diagrams, offline behavior, and sync specification |
| 10 | [API_SPEC.md](API_SPEC.md) | REST API contract: all endpoints, request/response formats, auth, error codes |
| 11 | [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) | PostgreSQL and SQLite schema with ER diagram, indexes, and retention policy |
| 12 | [SECURITY.md](SECURITY.md) | Security design: authentication, authorization, encryption, secrets, agent protection |
| 13 | [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE-based threat model with assets, trust boundaries, threat actors, and threat analysis |
| 14 | [PRIVACY.md](PRIVACY.md) | Privacy-by-design: what is collected, what is not, data minimization, retention, deletion |
| 15 | [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) | Phased development roadmap with tasks, dependencies, and definitions of done |
| 16 | [TASK_BREAKDOWN.md](TASK_BREAKDOWN.md) | Task list by component with descriptions, priorities, and expected deliverables |
| 17 | [GIT_WORKFLOW.md](GIT_WORKFLOW.md) | Branch strategy, commit conventions, PR process, review rules, protection policies |
| 18 | [TESTING_STRATEGY.md](TESTING_STRATEGY.md) | Testing approach for all categories: unit, integration, detection, AI, E2E, security |
| 19 | [DEPLOYMENT.md](DEPLOYMENT.md) | Deployment guide for local development, hackathon demo, and future production |
| 20 | [LIMITATIONS.md](LIMITATIONS.md) | Honest documentation of all system limitations and known gaps |
| 21 | [DECISIONS.md](DECISIONS.md) | Architecture Decision Records (ADRs) for all major and pending architectural decisions |
| 22 | [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) | This document: master index, reading order, and cross-document consistency review |

---

## Recommended Reading Order

The documents should be read in this order for a complete understanding of the project:

```
1.  PROJECT_OVERVIEW.md     ← Start here: understand the project concept
2.  REQUIREMENTS.md         ← What the system must do
3.  TECH_STACK.md           ← What technologies are used and why
4.  ARCHITECTURE.md         ← How the system is structured
5.  PROJECT_STRUCTURE.md    ← How the repository is organized
6.  FEATURES.md             ← What features exist and in which phase
7.  DETECTION_LOGIC.md      ← How detection works in detail
8.  AI_MODEL.md             ← How the AI component works
9.  DATA_FLOW.md            ← How data moves through the system
10. API_SPEC.md             ← The API contract
11. DATABASE_SCHEMA.md      ← The database design
12. SECURITY.md             ← Security design
13. THREAT_MODEL.md         ← What threats exist and how they are mitigated
14. PRIVACY.md              ← Privacy design
15. DEVELOPMENT_PLAN.md     ← The roadmap
16. TASK_BREAKDOWN.md       ← Specific tasks for each component
17. GIT_WORKFLOW.md         ← How to collaborate on code
18. TESTING_STRATEGY.md     ← How to test
19. DEPLOYMENT.md           ← How to deploy
20. LIMITATIONS.md          ← What the system cannot do
21. DECISIONS.md            ← Why decisions were made
```

---

## Document Dependencies

| Document | Depends on | Depended on by |
|---|---|---|
| PROJECT_OVERVIEW.md | None | Everything |
| REQUIREMENTS.md | PROJECT_OVERVIEW.md | ARCHITECTURE, FEATURES, DEVELOPMENT_PLAN |
| TECH_STACK.md | REQUIREMENTS.md | ARCHITECTURE, DEVELOPMENT_PLAN, DEPLOYMENT |
| ARCHITECTURE.md | TECH_STACK.md, REQUIREMENTS.md | DATA_FLOW, API_SPEC, DATABASE_SCHEMA, SECURITY |
| PROJECT_STRUCTURE.md | ARCHITECTURE.md | DEVELOPMENT_PLAN, TASK_BREAKDOWN |
| FEATURES.md | REQUIREMENTS.md | DEVELOPMENT_PLAN, TASK_BREAKDOWN |
| DETECTION_LOGIC.md | ARCHITECTURE.md | AI_MODEL.md, TESTING_STRATEGY.md |
| AI_MODEL.md | DETECTION_LOGIC.md, TECH_STACK.md | TASK_BREAKDOWN, TESTING_STRATEGY |
| DATA_FLOW.md | ARCHITECTURE.md | API_SPEC, DATABASE_SCHEMA |
| API_SPEC.md | DATA_FLOW.md, ARCHITECTURE.md | DATABASE_SCHEMA, TASK_BREAKDOWN |
| DATABASE_SCHEMA.md | API_SPEC.md, ARCHITECTURE.md | SECURITY, TASK_BREAKDOWN |
| SECURITY.md | DATABASE_SCHEMA.md, ARCHITECTURE.md | THREAT_MODEL, TASK_BREAKDOWN |
| THREAT_MODEL.md | SECURITY.md, ARCHITECTURE.md | LIMITATIONS |
| PRIVACY.md | DATA_FLOW.md, ARCHITECTURE.md | LIMITATIONS |
| DEVELOPMENT_PLAN.md | FEATURES.md, REQUIREMENTS.md | TASK_BREAKDOWN |
| TASK_BREAKDOWN.md | DEVELOPMENT_PLAN.md, PROJECT_STRUCTURE.md | None |
| GIT_WORKFLOW.md | PROJECT_STRUCTURE.md | None |
| TESTING_STRATEGY.md | DETECTION_LOGIC.md, API_SPEC.md | DEVELOPMENT_PLAN |
| DEPLOYMENT.md | TECH_STACK.md, ARCHITECTURE.md | None |
| LIMITATIONS.md | All technical docs | None |
| DECISIONS.md | All technical docs | None |

---

## Pre-Development Review

> This section documents the findings of a cross-document consistency review performed after all documentation files were created. Issues found are documented factually. None of the issues below are critical blockers, but they should be resolved before or during early implementation.

---

### ✅ Consistency Checks Passed

1. **Technology names are consistent.** `TECH_STACK.md` uses `FastAPI`, `PostgreSQL`, `Flutter`, `scikit-learn`, `psutil`, `watchdog`, `pywin32`, `joblib`, `httpx`, `dio`, `FCM` — and these same names appear consistently in `ARCHITECTURE.md`, `DEPLOYMENT.md`, `PROJECT_STRUCTURE.md`, and `TASK_BREAKDOWN.md`. No contradictions found.

2. **Database schema is consistent with API spec.** Every field returned by the API endpoints in `API_SPEC.md` has a corresponding column in `DATABASE_SCHEMA.md`. The `event_id`, `device_id`, `severity`, `timestamp`, `description`, `rule_ids`, `ai_anomaly_score`, `risk_score_at_event`, and `features` fields are present in both documents.

3. **Feature names are consistent.** Feature fields referenced in `DETECTION_LOGIC.md` (`has_encoded_args`, `is_signed_binary`, `path_legitimacy_score`, `parent_process_type`, `process_tree_depth`, `file_modification_rate`, `connects_on_unusual_port`, etc.) match those documented in `AI_MODEL.md` and referenced in `API_SPEC.md`'s event payload examples.

4. **Risk score range (0–100) is consistent.** Used in `REQUIREMENTS.md`, `DETECTION_LOGIC.md`, `ARCHITECTURE.md`, `AI_MODEL.md`, `DATA_FLOW.md`, `API_SPEC.md`, `DATABASE_SCHEMA.md`, and `FEATURES.md` — all consistently 0–100.

5. **Severity levels are consistent.** `LOW / MEDIUM / HIGH / CRITICAL` bands appear consistently across all documents that reference severity.

6. **Offline behavior is consistently described.** `REQUIREMENTS.md`, `ARCHITECTURE.md`, `DATA_FLOW.md`, `FEATURES.md`, and `LIMITATIONS.md` all agree: monitoring continues offline, events queue locally, sync on reconnect.

7. **MVP scope is consistently bounded.** `REQUIREMENTS.md`, `FEATURES.md`, `DEVELOPMENT_PLAN.md`, and `DECISIONS.md` all agree that macOS/Linux, automated quarantine, supervised ML, multi-device, and web dashboard are post-MVP.

8. **Privacy commitments are consistent.** `PRIVACY.md`, `DATA_FLOW.md`, `API_SPEC.md`, and `SECURITY.md` all agree that raw command-line arguments are not stored in the backend; the `features` JSONB field contains only derived boolean/numeric attributes.

9. **Project structure is consistent.** The directory tree in `PROJECT_STRUCTURE.md` is consistent with the file references in `TASK_BREAKDOWN.md` (e.g., `agent/monitoring/process_monitor.py`, `agent/detection/rule_engine.py`, `backend/app/api/events.py`).

10. **Git workflow is consistent with development plan.** `GIT_WORKFLOW.md` defines `main`/`dev`/feature branches and `DEVELOPMENT_PLAN.md` references phases without contradicting the workflow.

---

### ⚠️ Issues Found

---

#### Issue 1: WMI vs. psutil Polling for Process Creation — Decision Not Finalized

**Documents affected:** `TECH_STACK.md`, `ARCHITECTURE.md`, `DETECTION_LOGIC.md`

**Description:** `TECH_STACK.md` marks WMI for real-time process creation events as **PROPOSED — NOT FINAL**, with psutil polling as the MVP fallback. `ARCHITECTURE.md` mentions "WMI or Event Log for real-time process creation events (polling is the MVP fallback)." This is internally consistent, but the final approach for the MVP has not been decided.

**Recommendation:** Decide between WMI and polling before implementing `AGENT-002`. Polling is simpler; WMI is more real-time but less reliable. Document the decision in `DECISIONS.md` when resolved.

**Severity:** Low — both approaches produce the same telemetry format; the decision does not affect other documents.

---

#### Issue 2: SHAP Explainability Deferred But Referenced in Multiple Documents

**Documents affected:** `AI_MODEL.md`, `DETECTION_LOGIC.md`, `FEATURES.md`

**Description:** `AI_MODEL.md` notes that SHAP integration for per-feature alert explanations is "Phase 2 if it impacts MVP timeline." However, `DETECTION_LOGIC.md` includes an example alert output with `"Top contributing factors"` — which implies per-feature explanation. This creates a potential inconsistency: the example in DETECTION_LOGIC suggests a level of explainability that may not be present in the MVP.

**Recommendation:** Clarify in `DETECTION_LOGIC.md` that the contributing factors example is the intended format for Phase 2. The MVP alert will include the anomaly score but may not include per-feature breakdown. Add a note to the example.

**Severity:** Low — documentation inconsistency, not an architectural conflict.

---

#### Issue 3: Three Pending Decisions Must Be Resolved Before Implementation

**Documents affected:** `DECISIONS.md`, `TECH_STACK.md`, `ARCHITECTURE.md`, `DEPLOYMENT.md`

**Description:** Three decisions are marked as **DECISION PENDING**:
- `DECISION-PENDING-001`: Device authentication method (opaque token vs. JWT vs. mTLS)
- `DECISION-PENDING-002`: Real-time mobile updates (push vs. WebSocket vs. polling)
- `DECISION-PENDING-003`: Cloud hosting platform

These decisions must be resolved before the following tasks can proceed:
- `BACKEND-004` (device auth) requires `DECISION-PENDING-001`
- `MOBILE-006` / `BACKEND-008` (notifications) requires `DECISION-PENDING-002`
- `DEPLOYMENT.md` Phase 12 requires `DECISION-PENDING-003`

**Recommendation:** Resolve these decisions at the start of implementation, at minimum before reaching the dependent tasks.

**Severity:** Medium — blocking specific implementation tasks, though not blocking early phases.

---

#### Issue 4: Agent Autostart / Service Registration Not Fully Specified

**Documents affected:** `REQUIREMENTS.md` (FR-LM-03), `DEVELOPMENT_PLAN.md`, `DEPLOYMENT.md`, `PROJECT_STRUCTURE.md`

**Description:** `REQUIREMENTS.md` requires the agent to "survive system startup and re-register itself automatically" (FR-LM-03). However, `DEPLOYMENT.md` and `DEVELOPMENT_PLAN.md` both note Windows service registration as "(implementation TBD)" or "optional." The mechanism for making the agent a persistent Windows service is not specified.

**Recommendation:** Decide whether to use Windows Service Manager (`pywin32` service registration), Task Scheduler, or a startup Registry key for agent persistence. Document in `DECISIONS.md` and `DEVELOPMENT_PLAN.md`. This should be addressed in Phase 1 or Phase 2.

**Severity:** Medium — FR-LM-03 is a MUST requirement but the implementation is unspecified.

---

#### Issue 5: SQLite Encryption Not Addressed in MVP

**Documents affected:** `SECURITY.md`, `PRIVACY.md`, `DATABASE_SCHEMA.md`

**Description:** `SECURITY.md` notes that SQLite local database encryption is "Not implemented in MVP" and deferred to Phase 2 (SQLCipher or encrypted file system). However, the local SQLite database stores security events, alerts, and the offline event queue — some of which may include process paths and network metadata. `PRIVACY.md` recommends full-disk encryption as a compensating control.

This is a documented and accepted MVP trade-off, not an oversight. However, it should be flagged for Phase 2 priority.

**Recommendation:** Add SQLite encryption as a P1 Phase 2 task in `TASK_BREAKDOWN.md`. Ensure the agent setup instructions in `DEPLOYMENT.md` note that the user should have disk-level encryption (BitLocker) enabled.

**Severity:** Low — accepted MVP limitation; compensating control documented.

---

#### Issue 6: FCM Token Privacy Consideration Not Reflected in API Spec

**Documents affected:** `PRIVACY.md`, `API_SPEC.md`, `DATABASE_SCHEMA.md`

**Description:** `PRIVACY.md` notes that the FCM token "should be treated as a credential." The `DATABASE_SCHEMA.md` stores `fcm_token` in the `users` table without special protection notes. The `API_SPEC.md` does not include an endpoint for updating the FCM token (mobile apps regenerate FCM tokens on re-install).

**Recommendation:** Add a `PATCH /users/fcm-token` endpoint to `API_SPEC.md`. Note in `DATABASE_SCHEMA.md` that the FCM token should be treated with credential-level access control. Add `fcm_token` update handling to the mobile app lifecycle.

**Severity:** Low — functional gap that needs addressing before the notification system is complete.

---

#### Issue 7: No Explicit Data Deletion API Endpoint

**Documents affected:** `PRIVACY.md`, `API_SPEC.md`

**Description:** `PRIVACY.md` specifies that users must be able to delete their data and that device deregistration should remove associated data. However, `API_SPEC.md` does not include a `DELETE /users/me` or `DELETE /devices/{device_id}` endpoint.

**Recommendation:** Add account deletion and device deregistration endpoints to `API_SPEC.md`. These are privacy requirements, not optional features.

**Severity:** Medium — `PRIVACY.md` specifies this behavior but `API_SPEC.md` does not implement it.

---

### Summary of Issues

| Issue | Severity | Blocking | Recommended Resolution |
|---|---|---|---|
| 1. WMI vs. polling decision | Low | No | Decide before AGENT-002 |
| 2. SHAP explainability example inconsistency | Low | No | Clarify in DETECTION_LOGIC.md |
| 3. Three pending architecture decisions | Medium | Partially | Resolve at start of implementation |
| 4. Agent autostart mechanism unspecified | Medium | No | Decide and document in DECISIONS.md |
| 5. SQLite encryption deferred | Low | No | Add to Phase 2 task list |
| 6. FCM token update endpoint missing | Low | No | Add to API_SPEC.md |
| 7. Data deletion endpoints missing | Medium | No | Add to API_SPEC.md before privacy review |

**No critical architectural conflicts were found.** The documentation foundation is internally consistent and ready for implementation planning.

---

*Documentation review completed: 2026-09-16*
*Document version: 1.0 | Last updated: 2026-09-16*

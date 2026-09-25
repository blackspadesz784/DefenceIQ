# Architecture Decisions — AI-Powered Personal Security Layer

---

## Overview

This document records the major architectural decisions made for this project, using an Architecture Decision Record (ADR) style format. Each decision documents the context, options considered, decision made, rationale, and consequences.

Decisions that have not yet been finalized are explicitly marked:

> ⚠️ **DECISION PENDING**

---

## ADR-001 — Why a Laptop Security Agent Is Required

**Status:** DECIDED

**Context:**

The system aims to monitor security telemetry from a personal computer. There are two broad approaches: (1) a locally installed agent that has direct access to OS APIs, or (2) a purely cloud/remote approach that receives data the OS pushes externally.

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| Local agent (userspace) | Direct OS API access; works offline; no latency; monitors all activity | Requires installation; OS-specific; process can be killed |
| Kernel-level driver | Maximum visibility; harder to evade | Requires kernel signing; high implementation complexity; can cause system instability; out of scope for a student/hackathon project |
| No agent (cloud-only) | No local installation required | Cannot access OS APIs remotely; no offline capability; fundamentally limited visibility |

**Decision:** A **userspace Python agent** running locally on the laptop.

**Rationale:**
- Direct access to OS APIs (psutil, watchdog, winreg) is required for meaningful security telemetry.
- A kernel-level driver is unnecessary for the MVP scope and introduces significant complexity and risk.
- Cloud-only monitoring cannot observe process creation, file events, or Registry changes without a local component.
- Python provides the fastest development path and integrates naturally with the AI/ML stack.

**Consequences:**
- Agent can be killed by a sufficiently privileged process.
- Agent is platform-specific (Windows for MVP).
- Resource consumption must be carefully managed.

---

## ADR-002 — Why a Separate Mobile Dashboard Exists

**Status:** DECIDED

**Context:**

The system needs to provide the user with visibility into their laptop's security status when they are away from the laptop. Options include: mobile app, web dashboard, email alerts, or no remote visibility.

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| Android mobile app | Always with the user; push notifications; native UX | Requires mobile development; Flutter adds complexity |
| Web dashboard | Cross-platform; accessible from any browser | Requires separate web implementation; less convenient for quick checks |
| Email alerts only | No dashboard needed | No real-time view; limited interactivity; poor for history review |
| No remote visibility | Simpler | Defeats a core use case: monitoring while away from laptop |

**Decision:** **Android mobile app (Flutter)** as the primary remote dashboard.

**Rationale:**
- The core user need is visibility while away from the laptop — a mobile app satisfies this best.
- Push notifications are natively supported on Android and are the most reliable way to deliver urgent alerts.
- Flutter allows future iOS support without a full rewrite.
- A web dashboard can be added in Phase 2 without replacing the mobile app.

**Consequences:**
- Requires Flutter/Dart development expertise.
- Mobile app must be installed on the user's phone.
- Push notification delivery depends on FCM (third-party).

---

## ADR-003 — Why Rule-Based + AI Detection (Not AI Only)

**Status:** DECIDED

**Context:**

The system needs to detect suspicious behavior. The detection approach could be purely rule-based, purely AI/ML-based, or a combination.

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| Rules only | Explainable; deterministic; no training data needed | Misses novel threats; rules become stale; high maintenance |
| AI/ML only | Can detect novel patterns; adapts to new behaviors | Black box; requires labeled data; high false positive risk; not explainable without extra work |
| Rules + AI/ML (hybrid) | Combines strengths of both; rules provide baseline; AI provides anomaly detection | More complex to implement; requires careful integration |

**Decision:** **Hybrid: rule-based detection + AI/ML anomaly detection**, with risk scoring combining both signals.

**Rationale:**
- Rules provide deterministic, explainable detection for known patterns. They are essential for reliability.
- AI anomaly detection catches behavioral deviations that no rule covers — novel threats, unusual combinations.
- Neither approach alone is sufficient. Rules miss novel threats; AI alone has unacceptable false positive rates for MVP.
- Risk scoring as a combination layer means neither signal alone triggers an alert — multiple correlated signals are required.

**Consequences:**
- More complex detection pipeline.
- AI model must be trained and maintained separately.
- The detection pipeline requires clear documentation of how signals are combined (see [DETECTION_LOGIC.md](DETECTION_LOGIC.md)).

---

## ADR-004 — Why Anomaly Detection (Not Supervised Classification) for MVP

**Status:** DECIDED

**Context:**

The AI component could use supervised classification (requires labeled data: malicious vs. benign) or unsupervised anomaly detection (requires only benign data).

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| Supervised classifier | More accurate for known threat categories; trained on real malware samples | Requires labeled malicious training data that we do not have |
| Unsupervised anomaly detection | Requires only benign data; can be bootstrapped quickly | Cannot identify specific threat types; higher false positive risk |
| Rule-based only (no ML) | No training data required | Misses unlabeled/novel behaviors |

**Decision:** **Isolation Forest (unsupervised anomaly detection)** for the MVP.

**Rationale:**
- Labeled malicious training data is not available at the MVP stage.
- Anomaly detection can be bootstrapped from benign telemetry collected during normal system use.
- Isolation Forest is computationally efficient, well-understood, and integrates directly with scikit-learn.
- A supervised classifier will be developed in Phase 2 once labeled data strategies are defined.

**Consequences:**
- The MVP AI model cannot reliably classify specific malware types.
- False positive rate depends heavily on how representative the benign training data is.
- Documented clearly in [AI_MODEL.md](AI_MODEL.md) and [LIMITATIONS.md](LIMITATIONS.md).

---

## ADR-005 — Why Local AI Inference (Not Cloud AI) for MVP

**Status:** DECIDED

**Context:**

AI inference could run locally on the laptop or by sending feature vectors to a cloud AI service.

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| Local inference | Works offline; no privacy risk from cloud; no cloud API cost; lower latency | Less compute available; model size constrained |
| Cloud inference | More compute; can use larger models | Internet required; privacy concern (feature vectors sent to cloud); API cost; latency |

**Decision:** **Local inference only** in the MVP.

**Rationale:**
- Offline operation is a core requirement — cloud inference would break this.
- Sending feature vectors (even without raw content) to a third-party AI service raises privacy concerns that require user consent and a privacy review.
- Isolation Forest inference on tabular data is computationally trivial and does not require a GPU or cloud compute.
- Cloud inference can be added as an optional, opt-in feature in a future phase.

**Consequences:**
- Model complexity is constrained by the laptop's CPU and RAM.
- Deep learning approaches requiring GPU are out of scope for the MVP.

---

## ADR-006 — Why Local Monitoring Continues Offline

**Status:** DECIDED

**Context:**

If the laptop loses internet connectivity, the agent could either continue monitoring locally or pause until connectivity is restored.

**Decision:** **Monitoring, detection, risk scoring, and local alerting all continue without interruption during offline periods.**

**Rationale:**
- The core security value of the agent is always-on monitoring. An agent that stops when the internet goes down provides no protection during internet outages — which is exactly when an attacker might attempt to operate.
- Local detection does not require the backend.
- Events are queued and synchronized when connectivity is restored.
- This is a non-negotiable requirement, not a feature choice.

**Consequences:**
- Agent must have a fully independent local detection and storage pipeline.
- Synchronization logic must handle chronological ordering and deduplication.
- Mobile dashboard will show stale data during agent offline periods — this must be clearly communicated to the user.

---

## ADR-007 — Why the MVP Should Remain Simple

**Status:** DECIDED

**Context:**

Many additional detection capabilities, response mechanisms, and integrations are possible. The question is what to include in the MVP.

**Decision:** The MVP is intentionally scoped to:
- Windows 10/11 only.
- Five core monitor types (process, file, network, startup, command).
- Rule-based + basic anomaly detection.
- Read-only mobile dashboard.
- No automated process termination or file quarantine.

**Rationale:**
- Overengineering the MVP risks delivering nothing working. A working, demonstrable MVP with limited scope is more valuable than an ambitious, incomplete system.
- Each additional capability adds development time, testing complexity, and potential failure modes.
- The architecture is explicitly designed to be extensible — features can be added incrementally without redesign.
- The priority is a functional end-to-end pipeline, not feature completeness.

**Consequences:**
- macOS and Linux support deferred to post-MVP.
- Automated response deferred to Phase 2.
- Multi-device support deferred to Phase 2.

---

## ADR-008 — Why Automated Response Actions Are Controlled

**Status:** DECIDED

**Context:**

Should the agent automatically terminate suspicious processes or quarantine suspicious files when they are detected?

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| Full auto-response (no confirmation) | Fastest response to threats | High false positive risk: legitimate processes could be killed; data loss risk |
| No automated response (alert only) | Zero risk of false positive damage | No active defense; user must act manually |
| Controlled response (alert + user confirmation) | Balances speed with safety | Adds UI complexity; requires mobile action capability |

**Decision:** **MVP: alert and log only. No automated process termination or file quarantine.** Phase 2 will add user-confirmation-gated response actions.

**Rationale:**
- False positives are an accepted reality of behavioral detection. An automated response that acts on a false positive could terminate a legitimate, important process (database, editor, build system), causing data loss or work disruption.
- The risk of a damaging false-positive response exceeds the benefit of automated response at MVP stage.
- Real commercial EDR solutions have sophisticated quarantine pipelines with rollback, sandboxing, and forensic preservation — building a safe automated response system is itself a significant engineering effort.
- This decision is documented honestly in [LIMITATIONS.md](LIMITATIONS.md).

**Consequences:**
- No automated blocking in MVP.
- Users must respond to alerts manually.
- Phase 2 must define a safe, reversible response action framework before implementation.

---

## ADR-009 — Why PostgreSQL Over MongoDB for the Backend

**Status:** DECIDED

**Context:**

The backend stores structured data (users, devices, events, alerts) with clear relationships. The choice between a relational and document database was evaluated.

**Decision:** **PostgreSQL 14+**

**Rationale:**
- The data model has clear, well-defined relationships: users → devices → events → alerts.
- PostgreSQL JSONB support handles the flexible event `features` payload without sacrificing relational integrity.
- SQLAlchemy + Alembic provides a mature, well-documented ORM + migration path.
- PostgreSQL is widely supported by all major cloud hosting platforms.

**Consequences:**
- Schema migrations required for any structural changes.
- More operational overhead than a serverless document database (MongoDB Atlas, Firestore).
- More suitable for relational queries than document-oriented data access.

---

## ADR-010 — Why Python for Both Agent and Backend

**Status:** DECIDED

**Context:**

The agent could be written in a more systems-appropriate language (Go, Rust, C++) and the backend in a different language (Node.js, Go). Using Python for both was considered.

**Decision:** **Python 3.10+ for both agent and backend.**

**Rationale:**
- Shared language reduces context switching and allows code sharing (schemas, feature definitions, utilities).
- Python has the best ecosystem for both system monitoring (`psutil`, `watchdog`, `pywin32`) and AI/ML (`scikit-learn`, `numpy`, `pandas`).
- FastAPI is a best-in-class Python API framework.
- Development speed advantage for a hackathon-paced project.

**Consequences:**
- Higher resource consumption than Go or Rust.
- Python's GIL requires careful use of async/threading for the agent's concurrent monitoring tasks.
- Acceptable for the project's scale.

---

## DECISION-PENDING-001 — Device Authentication Method

**Status:** ⚠️ DECISION PENDING

**Context:**

How should the laptop agent authenticate with the backend? Options include:
1. Long-lived opaque API token (simple, but no expiry).
2. Short-lived JWT device token (more secure, but requires refresh logic).
3. Mutual TLS (strongest, but most complex to implement and manage).

**Open questions:**
- What is the right token lifetime for a device credential?
- Should device tokens expire and require periodic renewal?
- Is mTLS worth the added complexity for the MVP?

**Decision:** Pending. Will be resolved before implementing AGENT-013 and BACKEND-004.

---

## DECISION-PENDING-002 — Real-Time Mobile Updates (Push vs. WebSocket vs. Polling)

**Status:** ⚠️ DECISION PENDING

**Context:**

How should the mobile app receive real-time updates when new alerts are generated?

| Option | Description |
|---|---|
| FCM Push Notifications | Alert triggers FCM push; app fetches details when opened |
| WebSocket | Persistent connection from mobile to backend; real-time event stream |
| Polling | Mobile app polls the backend every N seconds |

**Open questions:**
- Is real-time delivery (WebSocket) necessary, or is FCM push + poll-on-open sufficient for the use case?
- WebSocket adds server-side complexity. Is it warranted for MVP?

**Decision:** Pending. FCM Push is the preferred default; WebSocket will be evaluated if polling proves too slow for the demo.

---

## DECISION-PENDING-003 — Cloud Hosting Platform

**Status:** ⚠️ DECISION PENDING

**Context:**

The backend must be deployed to a cloud platform for the hackathon demo. Candidates include Railway, Render, Fly.io, Heroku, and others.

**Criteria:** Free tier availability, ease of deployment, managed PostgreSQL support, Docker support.

**Decision:** Pending. Will be evaluated and chosen during Phase 12 (Deployment).

---

*Document version: 1.0 | Last updated: 2026-09-16*

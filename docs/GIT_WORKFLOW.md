# Git Workflow — AI-Powered Personal Security Layer

---

## Overview

This document defines the Git workflow for the project team. It is designed to be practical for a small team (2–5 people) working on a hackathon or early-stage project, while maintaining enough structure to keep the repository clean and avoid conflicts.

---

## 1. Repository Structure

The repository is a single monorepo containing all components:

```
AI-Personal-Security-Layer/
├── agent/
├── ai/
├── backend/
├── mobile/
├── tests/
└── docs/
```

All components live in the same repository for ease of cross-component coordination during early development.

---

## 2. Branch Strategy

### Main Branches

| Branch | Purpose |
|---|---|
| `main` | Stable, production-ready code. Protected. Only merge after review and all tests passing. |
| `dev` | Active integration branch. Features are merged here first. |

### Feature Branches

All new work is done on feature branches branched from `dev`.

**Branch naming convention:**

```
<type>/<component>/<short-description>
```

**Types:**

| Type | Use |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code restructure without behavior change |
| `test` | Adding or updating tests |
| `chore` | Build setup, config, dependency updates |

**Examples:**

```
feat/agent/process-monitor
feat/backend/auth-endpoints
fix/agent/rule-engine-and-logic
docs/threat-model-update
test/backend/event-endpoint-tests
chore/backend/add-alembic-setup
feat/mobile/dashboard-screen
feat/ai/isolation-forest-training
```

### Branch Lifecycle

```
main
  └── dev
        ├── feat/agent/process-monitor   ← Branch from dev
        ├── feat/backend/auth-endpoints  ← Branch from dev
        └── fix/agent/rule-engine-bug    ← Branch from dev
```

1. Branch from `dev` for all new work.
2. Commit and push work to your feature branch.
3. Open a Pull Request to merge into `dev`.
4. After review and approval, merge into `dev`.
5. When `dev` is stable and tested, merge `dev` into `main` as a release.

---

## 3. Commit Message Convention

Follow the **Conventional Commits** standard:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

**Scope:** Component name — `agent`, `backend`, `mobile`, `ai`, `docs`, `tests`

**Rules:**
- Summary is in lowercase, imperative tense: "add process monitor", not "Added process monitor" or "Adds process monitor"
- Summary is under 72 characters
- Body explains *why*, not just *what*

**Examples:**

```
feat(agent): add process monitor with psutil
```

```
fix(backend): correct JWT expiry validation in auth middleware

The expiry was being checked against server local time instead of UTC,
causing tokens to be rejected 5.5 hours early in IST timezone.
```

```
docs(agent): add inline docstrings to feature extractor

Added docstrings to all public methods in FeatureExtractor to clarify
expected input and output types.
```

```
chore(backend): add alembic migration for security_events table
```

---

## 4. Pull Requests

### When to open a PR

- When a feature branch is functionally complete and ready for review.
- Partial or work-in-progress PRs may be opened as **Draft PRs** for early feedback.

### PR Requirements

- **Title:** Follows the same convention as commit messages.
- **Description must include:**
  - What was changed and why.
  - How to test the change.
  - Any known limitations or follow-up tasks.
- **Linked issue/task ID** (if tracked in a task tracker).
- **Self-review:** Author reviews their own PR diff before requesting review.
- **Tests:** Any new code must have accompanying unit tests.

### PR Template (suggested):

```markdown
## Summary
Brief description of what this PR changes.

## Why
Explain why this change is needed.

## How to test
Steps to verify the change works.

## Checklist
- [ ] Code is linted and formatted (pre-commit passes)
- [ ] Unit tests added or updated
- [ ] Documentation updated if behavior changed
- [ ] No secrets or credentials in diff
```

---

## 5. Code Review

### Review expectations

- At least **one approval** required before merging to `dev`.
- Reviewer should check: correctness, security, readability, test coverage.
- The reviewer is not responsible for discovering all bugs — the author is responsible for writing correct code. The reviewer catches what the author missed.

### Review etiquette

- Comment on code, not the person.
- Distinguish between blocking issues ("This is incorrect, must be changed") and suggestions ("This could be cleaner, consider refactoring").
- Approve promptly — do not let PRs sit for more than 24 hours during active development.

---

## 6. Merge Rules

| Target Branch | Merge Method | Requirements |
|---|---|---|
| `dev` | Squash merge OR merge commit (team preference) | At least 1 approval; pre-commit checks pass |
| `main` | Merge commit | All `dev` integration tests pass; team review |

**Do not force push to `main` or `dev`** under any circumstances.

### Conflict resolution

- Rebase your feature branch on the latest `dev` before merging to resolve conflicts.
- Do not merge `main` into feature branches — rebase instead.
- If there is a complex conflict, resolve it locally and push the resolved version. Do not resolve conflicts in the GitHub UI for non-trivial cases.

---

## 7. Main Branch Protection

The `main` branch must be protected with:

- Require pull request before merging (no direct push).
- Require at least 1 approving review.
- Dismiss stale approvals when new commits are pushed.
- No force push allowed.

The `dev` branch should also be protected from force push.

---

## 8. Release Tags

When a significant milestone is reached (e.g., MVP complete), tag the commit on `main`:

```
git tag -a v0.1.0-mvp -m "MVP: End-to-end pipeline working"
git push origin v0.1.0-mvp
```

**Tagging convention:**

```
v<major>.<minor>.<patch>[-label]
```

Examples:
- `v0.1.0-mvp` — MVP release
- `v0.2.0` — Phase 2 release
- `v0.1.1-fix` — Patch on MVP

---

## 9. .gitignore Rules

At minimum, `.gitignore` must exclude:

```
# Python
__pycache__/
*.pyc
*.pyo
.venv/
venv/
*.egg-info/

# Environment variables (SECRETS)
.env
.env.*
!.env.example

# Databases
*.db
*.sqlite
*.sqlite3

# Flutter
.dart_tool/
.flutter-plugins
.flutter-plugins-dependencies
build/
*.apk

# IDE
.idea/
.vscode/
*.code-workspace

# OS
.DS_Store
Thumbs.db

# Training data (large files not in Git)
ai/data/benign/
ai/data/malicious/

# Model artifacts (managed separately if large)
# ai/models/*.joblib  ← Commented: may commit model artifacts if small
```

---

## 10. What Must Never Be Committed

- `.env` files with actual credentials.
- JWT signing keys.
- Database passwords.
- Firebase service account keys.
- Device tokens.
- API keys of any kind.
- Actual malware samples (even for AI training).
- User or system data from production.

If secrets are accidentally committed, rotate them immediately. Do not simply delete them from the latest commit — they remain in Git history.

---

*Document version: 1.0 | Last updated: 2026-09-16*

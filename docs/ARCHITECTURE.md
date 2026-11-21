# Architecture

## Overview

CloudGuard is a single FastAPI backend that owns three responsibilities:
scanning cloud resources for misconfigurations, scoring and persisting the
results, and serving both a REST API and a static dashboard that consumes
it. A standalone CLI shares the same core scanning/scoring code as the
API, so there is exactly one implementation of every check.

```
         ┌────────────────────────┐        ┌────────────────────────┐
         │  AWS Account           │        │  Azure Subscription     │
         │  (or AWS demo data)     │        │  (or Azure demo data)   │
         └────────────┬───────────┘        └────────────┬───────────┘
                      │ boto3                           │ Azure SDK
                      │ (or synthetic fallback)         │ (or synthetic fallback)
         ┌────────────▼───────────┐        ┌────────────▼───────────┐
         │  AWS Scanner Modules    │        │  Azure Scanner Modules  │
         │  S3 · IAM · SG · RDS    │        │  Storage · NSG · RBAC   │
         │  CloudTrail · EBS       │        │  SQL · Key Vault · Disk │
         └────────────┬───────────┘        └────────────┬───────────┘
                      │ list[Finding]                   │ list[Finding]
                      └────────────┬────────────────────┘
                    ┌──────────────▼───────────────┐
                    │      Scan Orchestrator        │
                    │  (provider selection: all /   │
                    │   aws / azure)                │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │       Risk Scoring Engine     │
                    │  overall + per-provider +     │
                    │  per-service scores           │
                    └──────────────┬───────────────┘
                                   │ ScanReport
                    ┌──────────────▼───────────────┐
                    │   Repository Layer (SQLAlchemy) │
                    │        SQLite / PostgreSQL      │
                    └──────────────┬───────────────┘
                                   │
                ┌──────────────────┼───────────────────┐
                │                  │                   │
        ┌───────▼──────┐  ┌────────▼───────┐  ┌───────▼──────┐
        │   REST API    │  │  HTML Report    │  │      CLI      │
        │   (FastAPI)   │  │   Generator     │  │ (bypasses API) │
        └───────┬──────┘  └────────────────┘  └──────────────┘
                │
        ┌───────▼──────┐
        │  Dashboard UI │
        │ (static HTML/JS)│
        └──────────────┘
```

## Core domain model

Every check produces a `Finding` (`backend/app/core/finding.py`) — the one
canonical unit that flows through the entire system. A `Finding` carries:

- `check_id` — a stable identifier (e.g. `S3_PUBLIC_WRITE`,
  `AZ_STORAGE_PUBLIC_BLOB`)
- `severity` — one of `info | low | medium | high | critical`
- `provider` — `aws` or `azure` (`CloudProvider` enum; GCP is a
  placeholder for a future provider)
- resource identity (`resource_type`, `resource_id`, `resource_name`, `region`)
- human-readable `title`/`description`/`remediation`
- `evidence` — the raw data that triggered the finding, for audit purposes
- `compliance` — zero or more `ComplianceMapping`s to framework controls
- a `fingerprint` — a stable hash of `check_id + resource_id + region`,
  used to recognize the "same" finding across repeated scans instead of
  creating duplicate rows every run

This normalized shape is what makes the risk engine, the reporting layer,
and the API all trivially generic: none of them know anything about S3 or
IAM specifically, they only know about `Finding`.

## Scanner design

Each scanner (`backend/app/scanners/*.py`) subclasses `BaseScanner` and
implements `run() -> list[Finding]`. Scanners are intentionally
self-contained: given a session manager, each one is independently
testable and independently useful. Each scanner class declares which
provider it belongs to (`provider = "aws"` / `"azure"`), and the
orchestrator hands it the matching session manager.

There are 12 scanner modules: 6 AWS (S3, IAM, EC2 Security Groups, RDS,
CloudTrail, EBS) and 6 Azure (Storage Accounts, Network Security Groups,
RBAC authorization, SQL Servers, Key Vaults, Managed Disks), for 42
checks in total. The orchestrator can run all of them or just one
provider (`provider` parameter: `all` / `aws` / `azure`).

### Live vs. demo mode

Each provider resolves live/demo independently:

- **AWS** — `AWSSessionManager` (`backend/app/scanners/base.py`) attempts
  to resolve a real boto3 session and validates it with a cheap
  `sts:GetCallerIdentity` call. If that fails for any reason (no
  credentials, expired token, no boto3 installed at all), `is_live` is
  `False` and every AWS scanner transparently falls back to a synthetic
  dataset defined in `app/scanners/demo_data.py`.
- **Azure** — `AzureSessionManager` (same module) first checks for any
  *signal* that a credential might exist (service-principal env vars,
  the `az` CLI, or a reachable instance metadata endpoint). If there is
  none, it goes straight to demo mode without invoking the
  `DefaultAzureCredential` chain, which can otherwise take seconds to
  fail in a credential-less environment. If a signal exists, it validates
  the credential with a token request for the management-plane scope and
  resolves the subscription (explicit `AZURE_SUBSCRIPTION_ID`, or the
  first visible subscription). On any failure it falls back to the
  synthetic dataset in `app/scanners/azure_demo_data.py`.

The overall scan mode is `live` when every selected provider is live,
`demo` when none is, and `mixed` when some are live and some fell back
to demo data.

This is the single most important architectural decision in the project:
**the exact same check logic runs in both modes.** `_evaluate_bucket()`,
`_evaluate_account()`, `_evaluate_nsg()`, etc. don't know or care
whether their input came from `boto3`/the Azure SDK or from a Python dict
literal — they operate on the same shape of data either way. This means:

- The project can be cloned and run with zero cloud setup and still produce
  a fully realistic, varied set of findings for both providers.
- There's no "fake" scanning logic to throw away later — pointing this at
  a real account is a configuration change (credentials), not a code
  change.
- The demo datasets (`demo_data.py`, `azure_demo_data.py`) double as test
  fixtures.

## Risk scoring model

See `backend/app/core/risk_engine.py`. The design goals were:

1. **Explainable.** No opaque ML model — every point of the score can be
   traced back to specific open findings.
2. **Severity-weighted.** `critical=12, high=9, medium=6, low=3, info=1`.
3. **Resistant to pileup.** An account with 40 buckets all missing the
   *same* low-severity control shouldn't crater the score the way 40
   independent critical issues would. A **diminishing-returns cap** is
   applied per severity tier: findings beyond the tier's threshold count
   at 25% weight.
4. **Monotonic and non-saturating.** An earlier linear model
   (`score = 100 - min(100, raw_penalty * scale)`) either saturated to a
   flat 0 for any realistically-sized account, or was too forgiving of a
   handful of criticals — there was no scale factor that satisfied both.
   The final model uses **exponential decay**:

   ```
   score = 100 * e^(-raw_penalty / K)
   ```

   This keeps the score strictly monotonic across the entire range: 5
   open criticals and 50 open criticals both score badly, but not
   identically, and the curve never artificially floors.

Per-service scores (`service_scores` in the API/dashboard) apply the exact
same formula to the subset of findings for that resource type, so a
dashboard can show "S3: 30, IAM: 53, RDS: 60, ..." rather than one opaque
number. Per-provider scores (`provider_scores`) do the same per cloud
provider ("AWS: 71, Azure: 58"), so a weak provider can't hide behind a
strong one — or vice versa.

## Persistence & finding lifecycle

Findings are not simply overwritten every scan. `app/models/repository.py`
uses each finding's `fingerprint` to detect "this is the same
misconfiguration as last time" and updates `last_seen_at` instead of
inserting a duplicate row. This is what makes a real finding lifecycle
possible: findings can be marked `resolved`, `suppressed`, or
`risk_accepted` via the API/dashboard, and they stay in that state across
subsequent scans unless the scanner re-detects the same fingerprint (in
which case a production system would typically re-open it — see
`docs/FUTURE_WORK.md`).

## API layer

FastAPI, with routes split by concern:

- `app/api/routes_scans.py` — trigger scans (sync or background), list/get
  scans, fetch findings for a specific scan
- `app/api/routes_findings.py` — cross-scan findings list/filter, status
  updates, dashboard summary, compliance summary
- `app/api/routes_reports.py` — HTML/JSON report generation from a
  persisted scan

A background-task path (`POST /api/scans`) and a synchronous path
(`POST /api/scans/sync`) are both provided. In demo mode a full scan
completes in under a second, so the dashboard uses the synchronous path
for a simpler UX; the async path exists for when live AWS API calls make
a scan take tens of seconds, and is a natural place to swap in a real task
queue (Celery/RQ + Redis) without changing the API contract.

## Frontend

Deliberately dependency-free: static HTML + vanilla JS + hand-written CSS,
served directly by FastAPI's `StaticFiles`. No build step, no npm install,
no framework — this keeps "clone and run" genuinely instant, and keeps the
project's complexity budget spent on the security engineering rather than
frontend tooling. The one non-trivial piece of UI is a hand-built radial
"posture gauge" (SVG, `frontend/static/js/gauge.js`) rather than a
generic progress bar, to make the security posture score legible at a
glance.

## Testing strategy

69 tests across four layers:

- **Scanner unit tests** (`test_scanners.py`, `test_azure.py`) — assert
  specific checks fire (and specific non-issues do *not* fire false
  positives) against the demo datasets, for both providers. The Azure
  tests also cover the live-fetch normalisation with mocked SDK clients,
  provider filtering, per-provider scoring, and the demo-mode fallback.
- **Risk engine unit tests** (`test_risk_engine.py`) — verify the scoring
  formula's properties directly (monotonicity, diminishing returns,
  boundary conditions) independent of any scanner.
- **Orchestrator tests** (`test_orchestrator.py`) — end-to-end demo scans,
  serialisation, and finding-idempotence across repeated scans.
- **API integration tests** (`test_api.py`) — exercise the full FastAPI
  app + SQLite persistence layer via `TestClient`, using an isolated
  temporary database per test session, including provider-scoped scans
  and provider filtering.

All 69 tests run with zero external dependencies (no cloud account, no
network), which is what makes them suitable for CI.

## Multi-cloud status

CloudGuard now scans AWS and Azure. The provider model was designed for
this from the start: `Finding` carries a `provider` field, each scanner
declares its provider, the orchestrator runs per-provider registries, and
scoring/reporting are provider-aware. Adding a third provider (GCP is the
placeholder in the `CloudProvider` enum) is additive — new scanner
classes + a new session manager — not a rewrite. See
`docs/FUTURE_WORK.md`.

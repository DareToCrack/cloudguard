# CloudGuard

**Cloud Security Posture Management (CSPM) for AWS.**

CloudGuard scans an AWS account for common misconfigurations across S3,
IAM, EC2 Security Groups, RDS, CloudTrail, and EBS; scores overall
security posture on a transparent 0–100 scale; maps every finding to CIS
AWS Foundations Benchmark controls; and produces a dashboard, JSON API,
CLI, and exportable HTML/JSON reports.

It runs against a real AWS account (read-only IAM permissions) **or**,
with zero configuration, against a bundled synthetic dataset — so the
entire tool can be evaluated end-to-end without any cloud credentials.

---

## Why this project exists

Most portfolio "security scanner" projects either (a) require a real AWS
account to demonstrate anything, or (b) are a single Python script that
prints a list of strings. CloudGuard is built the way a small security
team would actually build an internal CSPM tool: a real scanning engine
with a stable domain model, a persistence layer that tracks findings
across scans (not just point-in-time output), a REST API, a dashboard,
and a CLI — all sharing the same core logic, all covered by tests that
run in CI with no external dependencies.

## Features

- **6 scanner modules**: S3 buckets, IAM users/account settings, EC2
  Security Groups, RDS instances, CloudTrail, EBS volumes — 25 distinct
  checks in total.
- **Demo mode**: no AWS account needed. When no valid AWS credentials are
  found, every scanner automatically falls back to a realistic synthetic
  inventory, so `git clone && run` produces real output immediately.
- **Live mode**: point it at a real AWS account (via standard credential
  resolution — env vars, `~/.aws/credentials`, instance profile, SSO) and
  it scans for real, using the exact same check logic.
- **Explainable risk scoring**: a 0–100 posture score per account and per
  resource category, computed from an auditable formula (see
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#risk-scoring-model)) —
  not a black box.
- **Compliance mapping**: every finding maps to one or more CIS AWS
  Foundations Benchmark v3.0 controls, with a dedicated compliance
  coverage view.
- **Finding lifecycle**: findings persist across scans (fingerprinted, not
  duplicated) and can be marked resolved / suppressed / risk-accepted.
- **Dashboard**: a purpose-built web UI — posture gauge, severity
  breakdown, per-service scoring, filterable findings table, compliance
  view.
- **CLI**: run scans and generate reports without the API/dashboard at
  all — useful for CI pipelines or scheduled jobs.
- **Reports**: single-file HTML reports (print-to-PDF friendly) and JSON
  exports for integration with other tooling.
- **REST API**: fully documented via OpenAPI/Swagger at `/api/docs`.

## Quickstart

```bash
git clone <this-repo> cloudguard && cd cloudguard
./scripts/setup.sh
source .venv/bin/activate
./scripts/run.sh
```

Then open **http://localhost:8000** and click **Run scan**. No AWS
account required — CloudGuard runs in demo mode automatically.

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for full setup
instructions (Docker, live-AWS-account configuration, troubleshooting).

## Documentation

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, data flow, risk scoring model, scanner design, why key decisions were made |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Full install/run instructions (local, Docker, live AWS) |
| [`docs/USAGE.md`](docs/USAGE.md) | Dashboard walkthrough, CLI reference, API reference |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Required IAM permissions, secrets handling, threat model, security considerations |
| [`docs/FUTURE_WORK.md`](docs/FUTURE_WORK.md) | Known limitations, assumptions, and what a v2 would add |

## Project structure

```
cloudguard/
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── core/             # config, domain model, risk engine, orchestrator
│   │   ├── scanners/         # one module per AWS service scanned
│   │   ├── compliance/       # CIS AWS Foundations control mapping
│   │   ├── models/           # SQLAlchemy models + repository layer
│   │   ├── api/               # FastAPI routes + Pydantic schemas
│   │   ├── reporting/         # HTML report generator
│   │   └── main.py            # app entrypoint
│   ├── tests/                # pytest suite (40 tests)
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/                 # static dashboard (no build step)
│   ├── templates/index.html
│   └── static/{css,js}/
├── cli/cloudguard_cli.py     # standalone CLI
├── scripts/                  # setup / run / test / docker helper scripts
├── docs/
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Tech stack

Python 3.12 · FastAPI · SQLAlchemy · SQLite (swappable for PostgreSQL) ·
boto3 · Pydantic v2 · pytest · vanilla HTML/CSS/JS dashboard (no
build step, no framework) · Docker.

## License

MIT — see [`LICENSE`](LICENSE). Built as a portfolio/demonstration
project; see [`docs/SECURITY.md`](docs/SECURITY.md) before pointing this
at a production AWS account.

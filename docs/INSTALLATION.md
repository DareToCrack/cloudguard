# Installation

Three ways to run CloudGuard, from simplest to most production-like.

## Prerequisites

- **Python 3.11+** (developed and tested on 3.12)
- **pip**
- Optional: **Docker** + **Docker Compose**, if you'd rather not manage a
  local virtualenv
- Optional: an **AWS account with read-only credentials**, if you want to
  scan a real account instead of using the bundled demo data

Nothing else is required — SQLite ships with Python, and the dashboard is
static HTML/JS with no build step.

---

## Option 1 — Local Python (recommended for development)

```bash
git clone <this-repo> cloudguard
cd cloudguard

# One-time setup: creates .venv, installs dependencies, runs the test suite
./scripts/setup.sh

# Activate the virtualenv for subsequent commands
source .venv/bin/activate

# Start the API + dashboard
./scripts/run.sh
```

Open **http://localhost:8000**. Click **Run scan** — no AWS account is
required; CloudGuard automatically detects there are no valid AWS
credentials and runs against its bundled demo dataset.

- Dashboard: `http://localhost:8000/`
- REST API docs (Swagger UI): `http://localhost:8000/api/docs`
- Health check: `http://localhost:8000/api/health`

For auto-reload during development:

```bash
./scripts/run.sh --reload
```

### Manual setup (if you don't want to use `scripts/setup.sh`)

```bash
cd backend
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements-dev.txt
cp ../.env.example .env
python -m pytest              # optional: verify the install
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Option 2 — Docker / Docker Compose

```bash
git clone <this-repo> cloudguard
cd cloudguard
./scripts/docker_run.sh
```

This builds the image and starts the container, waiting for the health
check to pass. Once it does:

- Dashboard: `http://localhost:8000/`
- API docs: `http://localhost:8000/api/docs`

Findings are persisted to a named Docker volume (`cloudguard-data`), so
they survive container restarts.

Manual equivalent:

```bash
docker compose build
docker compose up -d
docker compose logs -f      # tail logs
docker compose down         # stop (data volume is preserved)
docker compose down -v      # stop AND delete all scan history
```

---

## Option 3 — CLI only (no server)

Useful for CI pipelines, scheduled scans, or if you just want a report
file without running the dashboard.

```bash
source .venv/bin/activate     # after running scripts/setup.sh once
python cli/cloudguard_cli.py scan
python cli/cloudguard_cli.py scan --output report.html --format html
python cli/cloudguard_cli.py scan --output report.json --format json
python cli/cloudguard_cli.py list-checks
```

---

## Scanning a real AWS account

By default, CloudGuard scans in **demo mode** — no configuration needed.
To scan a real account instead, provide valid AWS credentials via any of
the standard mechanisms boto3 supports:

**Environment variables:**
```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...        # if using temporary credentials
export AWS_DEFAULT_REGION=us-east-1
./scripts/run.sh
```

**A named profile** (`~/.aws/credentials`):
```bash
# via the dashboard's "Run scan" it uses the default profile;
# via the CLI, pass --profile explicitly:
python cli/cloudguard_cli.py scan --profile my-readonly-profile --region us-east-1
```

**Via Docker**, mount your local AWS config read-only (uncomment the
volume line in `docker-compose.yml`):
```yaml
volumes:
  - ${HOME}/.aws:/home/cloudguard/.aws:ro
```

**Required IAM permissions:** see [`SECURITY.md`](SECURITY.md#required-iam-permissions)
for the minimal read-only policy. CloudGuard never calls a mutating AWS
API — every permission it needs is a `Describe*`/`Get*`/`List*` action.

If credentials are present but invalid/expired, or a specific scanner's
API calls fail partway through (e.g. missing permission for one service),
CloudGuard logs the error and falls back to demo data for that scanner
rather than crashing the whole scan — check the `scanner_errors` field in
the scan result / dashboard.

---

## Verifying the installation

```bash
./scripts/test.sh
```

Expected output: `40 passed` in under 15 seconds, no network access
required.

You can also smoke-test the running server directly:

```bash
curl http://localhost:8000/api/health
curl -X POST http://localhost:8000/api/scans/sync \
  -H "Content-Type: application/json" -d '{"region":"us-east-1"}'
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Install Python 3.11+ from python.org or your OS package manager. |
| `pip install` fails on a specific package | Ensure you're using Python 3.11+; some pinned versions require it. Re-run `./scripts/setup.sh`. |
| Port 8000 already in use | `CLOUDGUARD_API_PORT=8001 ./scripts/run.sh`, or stop the other process. |
| Dashboard loads but "Run scan" hangs | Check `curl http://localhost:8000/api/health`; if that fails, the API isn't running — check terminal output / `docker compose logs`. |
| Scan runs but shows 0 findings unexpectedly | You may have valid AWS credentials pointing at an already well-configured account — check the `mode` field in the scan result (`live` vs `demo`) to confirm which one ran. |
| `ModuleNotFoundError` when running the CLI directly | Activate the virtualenv first (`source .venv/bin/activate`), or run via `scripts/setup.sh` which installs everything into it. |
| SQLite "database is locked" under heavy concurrent use | Expected for SQLite under concurrent writes; for production/multi-user deployments, set `CLOUDGUARD_DATABASE_URL` to a PostgreSQL connection string. |
| Docker build fails to reach PyPI | Check your network/proxy settings; corporate proxies may need `--build-arg HTTP_PROXY=...` added to the Dockerfile. |

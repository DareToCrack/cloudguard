# Installation

Three ways to run CloudGuard, from simplest to most production-like.

## Prerequisites

- **Python 3.11+** (developed and tested on 3.12)
- **pip**
- Optional: **Docker** + **Docker Compose**, if you'd rather not manage a
  local virtualenv
- Optional: an **AWS account with read-only credentials** and/or an
  **Azure subscription with Reader access**, if you want to scan real
  accounts instead of using the bundled demo data
- Optional: the **Azure CLI** (`az`), the simplest way to authenticate
  for live Azure scanning

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

Open **http://localhost:8000**. Click **Run scan** — no cloud account is
required; CloudGuard automatically detects there are no valid
credentials and runs against its bundled demo datasets (AWS and Azure).

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
python cli/cloudguard_cli.py scan --provider azure
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

## Scanning a real Azure subscription

By default, CloudGuard scans Azure in **demo mode** too. To scan a real
subscription, authenticate via any mechanism `azure-identity`'s
`DefaultAzureCredential` supports:

**Azure CLI (simplest for local use):**
```bash
az login
az account set --subscription <subscription-id>   # if you have several
./scripts/run.sh
```

**Service principal (for servers / CI):**
```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...        # application (client) ID
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...  # optional: defaults to the first visible subscription
./scripts/run.sh
```

**Managed identity (when running on Azure):** no configuration needed —
assign the Reader role to the VM / App Service identity at subscription
scope and CloudGuard picks it up automatically. Note that a
system-assigned managed identity is only auto-detected when the instance
metadata endpoint is reachable from the process; see
[`SECURITY.md`](SECURITY.md#azure-permissions) for details.

**Required Azure permissions:** the built-in **Reader** role at
subscription scope is sufficient — CloudGuard only calls read-only ARM
`list`/`get` operations. See
[`SECURITY.md`](SECURITY.md#azure-permissions) for the exact
actions and how to assign the role.

To scan only Azure from the dashboard, pick **Azure** in the provider
dropdown next to **Run scan**; from the CLI, use
`--provider azure`. If Azure credentials are valid but AWS credentials
are not (or vice versa), the scan runs in **mixed** mode — live for one
provider, demo for the other — and the mode pill says so.

---

## Verifying the installation

```bash
./scripts/test.sh
```

Expected output: `69 passed`, no network access required.

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
| Scan runs but shows 0 findings unexpectedly | You may have valid credentials pointing at an already well-configured account — check the `mode` field in the scan result (`live` vs `demo` vs `mixed`) to confirm which one ran. |
| Azure scan stays in demo mode after `az login` | Check `az account show` reports the subscription you expect, and that the signed-in identity has at least Reader access to it. CloudGuard logs the reason at startup — look for "No live Azure credentials available". |
| `azure-identity` errors about interactive login | CloudGuard excludes the interactive-browser credential by design — use `az login` or service-principal env vars instead. |
| API errors mentioning a missing `provider` column | Your `cloudguard.db` predates the Azure update and the automatic migration did not run. Stop the server, delete `backend/cloudguard.db` (scan history is lost), and restart — the database is recreated with the new schema. |
| `ModuleNotFoundError` when running the CLI directly | Activate the virtualenv first (`source .venv/bin/activate`), or run via `scripts/setup.sh` which installs everything into it. |
| SQLite "database is locked" under heavy concurrent use | Expected for SQLite under concurrent writes; for production/multi-user deployments, set `CLOUDGUARD_DATABASE_URL` to a PostgreSQL connection string. |
| Docker build fails to reach PyPI | Check your network/proxy settings; corporate proxies may need `--build-arg HTTP_PROXY=...` added to the Dockerfile. |

# Usage

## Dashboard walkthrough

1. **Run a scan.** Click **▶ Run scan** in the top bar. In demo mode this
   completes in well under a second; against a real account it depends on
   account size (typically a few seconds).
2. **Dashboard tab.** Shows the overall posture gauge (0–100, letter
   grade), a severity breakdown, per-resource-category scores, top-line
   stats, and a preview of the highest-severity findings.
3. **Findings tab.** The full findings table — search by title/resource
   name, filter by severity or resource type, and change a finding's
   status (`open` / `resolved` / `suppressed` / `risk_accepted`) inline.
   Status changes take effect immediately via the API; they persist across
   future scans (matched by fingerprint).
4. **Compliance tab.** Every CIS AWS Foundations Benchmark control that
   has at least one open finding mapped to it, sorted by highest severity
   first — useful for an "are we ready for an audit" view.
5. **Export report.** Opens a self-contained HTML report for the most
   recent scan in a new tab — print it to PDF, email it, or archive it as
   point-in-time evidence.

The mode pill next to the scan button (`DEMO MODE` / `LIVE MODE`) always
tells you which data source produced the current results.

## CLI reference

```
python cli/cloudguard_cli.py scan [options]
python cli/cloudguard_cli.py list-checks
```

### `scan`

| Flag | Default | Description |
|---|---|---|
| `--region` | `us-east-1` | AWS region to scan (live mode only; demo mode ignores this) |
| `--profile` | none | Named AWS CLI profile to use |
| `--output` | none | File path to write a report to |
| `--format` | `json` | `html` or `json`, used with `--output` |

Examples:

```bash
# Console summary only, no file output
python cli/cloudguard_cli.py scan

# Full JSON report for scripting/CI
python cli/cloudguard_cli.py scan --output findings.json --format json

# Printable HTML report against a real account
python cli/cloudguard_cli.py scan --profile prod-readonly --region us-east-1 \
  --output posture-report.html --format html
```

Exit behavior: the CLI always exits 0 on a completed scan (even if
findings were detected) — findings are the expected output of a working
scanner, not a tool failure. Scanner-level errors (e.g. a missing IAM
permission for one service) are printed but do not abort the scan for
other services.

### `list-checks`

Prints every registered scanner module and the AWS service it targets —
useful for confirming what CloudGuard will and won't check before running
it against a real account.

## API reference

Full interactive documentation is auto-generated at `/api/docs`
(Swagger UI) and `/api/redoc` whenever the server is running. Key
endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Liveness/health check |
| `POST` | `/api/scans/sync` | Run a scan synchronously, return the result |
| `POST` | `/api/scans` | Start a scan in the background, returns `scan_id` immediately |
| `GET` | `/api/scans` | List past scans |
| `GET` | `/api/scans/{scan_id}` | Get a specific scan's summary |
| `GET` | `/api/scans/{scan_id}/findings` | Get all findings from a specific scan |
| `GET` | `/api/findings` | List/filter open findings across all scans (`?severity=`, `?resource_type=`, `?search=`) |
| `PATCH` | `/api/findings/{finding_id}` | Update a finding's status |
| `GET` | `/api/dashboard` | Aggregated dashboard summary + score trend |
| `GET` | `/api/compliance/summary` | Open findings grouped by compliance control |
| `GET` | `/api/reports/{scan_id}/html` | Self-contained HTML report |
| `GET` | `/api/reports/{scan_id}/json` | Full JSON report |

Example: trigger a scan and fetch its findings with `curl`:

```bash
SCAN=$(curl -s -X POST http://localhost:8000/api/scans/sync \
  -H "Content-Type: application/json" -d '{"region":"us-east-1"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")

curl -s "http://localhost:8000/api/scans/$SCAN/findings" | python3 -m json.tool
```

## Understanding the risk score

The posture score is 0–100 (higher is better), with a letter grade:

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

The score is driven entirely by **open** findings, weighted by severity
(`critical > high > medium > low > info`), with diminishing returns
applied to large numbers of same-severity findings so that one repeated
low-severity issue across many resources doesn't dominate the score the
way a handful of criticals does. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#risk-scoring-model) for the exact
formula. Marking a finding `resolved`, `suppressed`, or `risk_accepted`
removes it from the score calculation immediately.

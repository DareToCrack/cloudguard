#!/usr/bin/env bash
# CloudGuard - start the API server + dashboard locally.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/backend"

if [ -d "../.venv" ]; then
  # shellcheck disable=SC1091
  source ../.venv/bin/activate
fi

HOST="${CLOUDGUARD_API_HOST:-0.0.0.0}"
PORT="${CLOUDGUARD_API_PORT:-8000}"
RELOAD_FLAG="${1:-}"

echo "==> Starting CloudGuard on http://localhost:${PORT}"
echo "==> Dashboard:  http://localhost:${PORT}/"
echo "==> API docs:   http://localhost:${PORT}/api/docs"
echo ""

if [ "$RELOAD_FLAG" == "--reload" ]; then
  exec python -m uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
else
  exec python -m uvicorn app.main:app --host "$HOST" --port "$PORT"
fi

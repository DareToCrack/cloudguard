#!/usr/bin/env bash
# CloudGuard - run the full test suite with coverage.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/backend"

if [ -d "../.venv" ]; then
  # shellcheck disable=SC1091
  source ../.venv/bin/activate
fi

echo "==> Running CloudGuard test suite"
python -m pytest -v --cov=app --cov-report=term-missing "$@"

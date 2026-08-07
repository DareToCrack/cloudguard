#!/usr/bin/env bash
# CloudGuard - build and run via Docker Compose.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Install Docker Desktop / Docker Engine and re-run." >&2
  exit 1
fi

COMPOSE_CMD="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
fi

echo "==> Building CloudGuard image"
$COMPOSE_CMD build

echo "==> Starting CloudGuard"
$COMPOSE_CMD up -d

echo ""
echo "==> CloudGuard is starting. Waiting for health check..."
for _ in $(seq 1 20); do
  if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
    echo "==> CloudGuard is up: http://localhost:8000"
    exit 0
  fi
  sleep 1
done

echo "WARNING: health check did not pass within 20s - check logs with:"
echo "  $COMPOSE_CMD logs -f"

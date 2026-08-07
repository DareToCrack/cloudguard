# CloudGuard API - multi-stage build
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies (kept minimal - no compiler toolchain needed for
# the pinned pure-Python/wheel-only dependency set in requirements.txt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for better layer caching
COPY backend/requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

# Create a non-root user, and a data directory for the SQLite DB when
# running via docker-compose (see docker-compose.yml's volume mount).
RUN useradd --create-home --shell /bin/bash cloudguard \
    && mkdir -p /data \
    && chown -R cloudguard:cloudguard /data
USER cloudguard

# Copy application code
COPY --chown=cloudguard:cloudguard backend/app /app/app
COPY --chown=cloudguard:cloudguard frontend /app/frontend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

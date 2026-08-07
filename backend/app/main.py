"""CloudGuard FastAPI application entrypoint."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes_findings import router as findings_router
from app.api.routes_reports import router as reports_router
from app.api.routes_scans import router as scans_router
from app.core.config import settings
from app.core.logging_config import configure_logging
from app.models.database import init_db

configure_logging()
logger = logging.getLogger("cloudguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("CloudGuard API started (env=%s, debug=%s)", settings.environment, settings.debug)
    yield
    logger.info("CloudGuard API shutting down")


app = FastAPI(
    title="CloudGuard API",
    description="Cloud Security Posture Management (CSPM) REST API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers_and_timing(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
    # Baseline security headers - a real deployment should also set these at
    # the reverse proxy / CDN layer.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/api/health", tags=["meta"])
def health_check():
    return {"status": "ok", "app": settings.app_name, "version": "1.0.0", "environment": settings.environment}


app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router)


# -- static frontend -----------------------------------------------------
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")

    @app.get("/", include_in_schema=False)
    def serve_dashboard():
        return FileResponse(str(FRONTEND_DIR / "templates" / "index.html"))

    @app.get("/{page_name}.html", include_in_schema=False)
    def serve_page(page_name: str):
        target = FRONTEND_DIR / "templates" / f"{page_name}.html"
        if target.exists():
            return FileResponse(str(target))
        return FileResponse(str(FRONTEND_DIR / "templates" / "index.html"))

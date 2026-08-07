"""Centralized application configuration.

Settings are loaded from environment variables (with sane local defaults)
using pydantic-settings, following the twelve-factor app pattern. Nothing
sensitive is hard-coded; see `.env.example` for the full list of supported
variables.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CLOUDGUARD_", extra="ignore")

    # -- application ------------------------------------------------------
    app_name: str = "CloudGuard"
    environment: str = "development"          # development | staging | production
    debug: bool = True
    secret_key: str = "change-me-in-production-use-a-random-64-char-string"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # -- database -----------------------------------------------------------
    database_url: str = "sqlite:///./cloudguard.db"

    # -- auth ---------------------------------------------------------------
    access_token_expire_minutes: int = 60
    jwt_algorithm: str = "HS256"

    # -- aws ------------------------------------------------------------
    aws_profile: str | None = None
    aws_default_region: str = "us-east-1"

    # -- scanning ---------------------------------------------------------
    scan_regions: str = "us-east-1,us-west-2"   # comma-separated
    findings_retention_days: int = 365

    # -- cors -----------------------------------------------------------
    cors_origins: str = "http://localhost:3000,http://localhost:8000"

    @property
    def scan_region_list(self) -> list[str]:
        return [r.strip() for r in self.scan_regions.split(",") if r.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()

"""Base scanner interface and AWS session management.

Every concrete scanner (S3, IAM, EC2 Security Groups, RDS, CloudTrail, ...)
subclasses `BaseScanner` and implements `run()`, returning a list of
`Finding` objects. Scanners are self-contained and independently testable.

CloudGuard supports two data modes:

1. **Live mode** - a real AWS session (via boto3) is used, driven by
   standard AWS credential resolution (env vars, shared config, instance
   profile, SSO, etc.).
2. **Demo mode** - when no valid AWS credentials are available (e.g. running
   this project as a portfolio demo without a real AWS account), scanners
   fall back to a realistic synthetic resource inventory defined in
   `app.scanners.demo_data`. This lets the entire tool be built, run, and
   evaluated end-to-end with zero cloud dependencies while keeping the
   scanner logic byte-for-byte identical to what would run against a real
   account.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("cloudguard.scanners")

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

    BOTO3_AVAILABLE = True
except ImportError:  # boto3 is an optional dependency for demo-only usage
    BOTO3_AVAILABLE = False


class AWSSessionManager:
    """Resolves an AWS session and reports whether live credentials exist."""

    def __init__(self, profile: str | None = None, region: str = "us-east-1") -> None:
        self.profile = profile
        self.region = region
        self._session = None
        self._live = False

    @property
    def is_live(self) -> bool:
        """True if a real, validated AWS session is available."""
        if self._session is None:
            self._resolve()
        return self._live

    def _resolve(self) -> None:
        if not BOTO3_AVAILABLE:
            logger.info("boto3 not installed - running in demo mode.")
            self._live = False
            return
        try:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            # Cheap call that fails fast if no credentials are configured.
            sts = session.client("sts")
            sts.get_caller_identity()
            self._session = session
            self._live = True
            logger.info("AWS live session established (region=%s).", self.region)
        except (NoCredentialsError, ClientError, BotoCoreError, Exception) as exc:  # noqa: BLE001
            logger.info("No live AWS credentials available (%s) - using demo mode.", exc)
            self._session = None
            self._live = False

    def client(self, service: str):
        if not self.is_live:
            raise RuntimeError("No live AWS session - cannot create a boto3 client in demo mode.")
        return self._session.client(service, region_name=self.region)


class BaseScanner(ABC):
    """Abstract base for all resource scanners."""

    #: short, human-readable name used in logs / UI
    name: str = "base"
    #: AWS service this scanner targets, used for grouping in reports
    service: str = "generic"

    def __init__(self, session_manager: AWSSessionManager) -> None:
        self.session_manager = session_manager

    @abstractmethod
    def run(self) -> list[Any]:
        """Execute all checks for this scanner and return Finding objects."""
        raise NotImplementedError

    def _demo_or_live(self, live_fn, demo_fn):
        """Helper: dispatch to live AWS calls or synthetic demo data."""
        if self.session_manager.is_live:
            try:
                return live_fn()
            except Exception:  # noqa: BLE001
                logger.exception("%s: live scan failed, falling back to demo data.", self.name)
                return demo_fn()
        return demo_fn()

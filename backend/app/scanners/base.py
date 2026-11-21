"""Base scanner interface and cloud session management.

Every concrete scanner (S3, IAM, EC2 Security Groups, RDS, CloudTrail,
Azure Storage, Azure NSGs, ...) subclasses `BaseScanner` and implements
`run()`, returning a list of `Finding` objects. Scanners are
self-contained and independently testable.

CloudGuard supports two data modes, per provider:

1. **Live mode** - a real cloud session (boto3 for AWS, Azure SDK for
   Azure) is used, driven by standard credential resolution.
2. **Demo mode** - when no valid credentials are available (e.g. running
   this project as a portfolio demo without a real cloud account),
   scanners fall back to a realistic synthetic resource inventory defined
   in `app.scanners.demo_data` (AWS) or
   `app.scanners.azure_demo_data` (Azure). This lets the entire tool be
   built, run, and evaluated end-to-end with zero cloud dependencies
   while keeping the scanner logic byte-for-byte identical to what would
   run against a real account.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("cloudguard.scanners")

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

    BOTO3_AVAILABLE = True
except ImportError:  # boto3 is an optional dependency for demo-only usage
    BOTO3_AVAILABLE = False

try:
    from azure.core.exceptions import AzureError
    from azure.identity import DefaultAzureCredential

    AZURE_AVAILABLE = True
except ImportError:  # Azure SDKs are optional for demo-only usage
    AZURE_AVAILABLE = False

# Management-plane scope used to validate an Azure credential. Requesting
# a token for this scope is a cheap, read-only call that fails fast when
# no credential is configured.
AZURE_MANAGEMENT_SCOPE = "https://management.azure.com/.default"

# Well-known built-in Azure RBAC role definition IDs, used by the
# authorization scanner to recognise broad assignments without an extra
# lookup round-trip per assignment.
AZURE_ROLE_OWNER_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
AZURE_ROLE_CONTRIBUTOR_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"


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


# The credential-signal pre-check (env vars, `az` CLI, IMDS) depends only
# on the process environment, so its result is cached process-wide: every
# scan creates a fresh session manager, and re-probing the instance
# metadata endpoint on each one would add latency for no benefit.
_CREDENTIAL_SIGNALS_CACHE: bool | None = None


def _azure_credential_signals_present() -> bool:
    """Cheap heuristic: is there any plausible Azure credential source?

    `DefaultAzureCredential` tries a long chain of credential types, some
    of which (managed identity) involve network calls with multi-second
    timeouts. In a plain local/demo environment with no Azure setup at
    all, invoking the full chain on every scan would make demo mode
    noticeably slow for no benefit, so we first check for any *signal*
    that a credential might exist:

    - service-principal / workload-identity env vars
    - the `az` CLI on PATH (Azure CLI login)
    - a reachable instance metadata endpoint (managed identity on an
      Azure VM)

    If none of these is present, there is no credential to find and the
    caller can go straight to demo mode. This deliberately does NOT
    cover a system-assigned managed identity on a host where the metadata
    endpoint is unreachable from this process - see docs/SECURITY.md.
    """
    global _CREDENTIAL_SIGNALS_CACHE
    if _CREDENTIAL_SIGNALS_CACHE is not None:
        return _CREDENTIAL_SIGNALS_CACHE

    env_signals = (
        "AZURE_CLIENT_ID" in os.environ
        or "AZURE_CLIENT_SECRET" in os.environ
        or "AZURE_TENANT_ID" in os.environ
        or "AZURE_FEDERATED_TOKEN_FILE" in os.environ
        or "IDENTITY_ENDPOINT" in os.environ
        or "MSI_ENDPOINT" in os.environ
    )
    cli_present = shutil.which("az") is not None
    imds_reachable = False
    if not env_signals and not cli_present:
        # Only probe IMDS when nothing else suggests a credential exists.
        try:
            with socket.create_connection(("169.254.169.254", 80), timeout=0.3):
                imds_reachable = True
        except OSError:
            imds_reachable = False

    _CREDENTIAL_SIGNALS_CACHE = bool(env_signals or cli_present or imds_reachable)
    return _CREDENTIAL_SIGNALS_CACHE


class AzureSessionManager:
    """Resolves an Azure session and reports whether live credentials exist.

    Live mode uses `azure-identity`'s DefaultAzureCredential chain
    (service-principal env vars, workload identity, Azure CLI login,
    managed identity). Only read-only ARM calls are ever made - every
    scanner uses list/get operations. The interactive-browser credential
    is excluded: a scanner must never block waiting for a user to
    complete a browser login.
    """

    # Management-client class per short name, imported lazily so a
    # missing azure-mgmt-* package degrades to demo mode instead of an
    # import error at module load.
    _CLIENT_MODULES = {
        "storage": ("azure.mgmt.storage", "StorageManagementClient"),
        "network": ("azure.mgmt.network", "NetworkManagementClient"),
        "authorization": ("azure.mgmt.authorization", "AuthorizationManagementClient"),
        "sql": ("azure.mgmt.sql", "SqlManagementClient"),
        "keyvault": ("azure.mgmt.keyvault", "KeyVaultManagementClient"),
        "compute": ("azure.mgmt.compute", "ComputeManagementClient"),
        "resource": ("azure.mgmt.resource", "SubscriptionClient"),
    }

    def __init__(self, subscription_id: str | None = None) -> None:
        self.subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        self._credential = None
        self._clients: dict[str, Any] = {}
        self._live = False
        self._resolved = False

    @property
    def is_live(self) -> bool:
        """True if a real, validated Azure credential is available."""
        if not self._resolved:
            self._resolve()
        return self._live

    def _resolve(self) -> None:
        self._resolved = True
        if not AZURE_AVAILABLE:
            logger.info("Azure SDKs not installed - running Azure scanners in demo mode.")
            self._live = False
            return
        if not _azure_credential_signals_present():
            logger.info("No Azure credential signals found - running Azure scanners in demo mode.")
            self._live = False
            return
        try:
            credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
            # Cheap call that fails fast if no credential is configured.
            credential.get_token(AZURE_MANAGEMENT_SCOPE)
            self._credential = credential
            self.subscription_id = self._resolve_subscription_id(credential)
            if not self.subscription_id:
                logger.info("Azure credential valid but no subscription visible - using demo mode.")
                self._live = False
                return
            self._live = True
            logger.info("Azure live session established (subscription=%s).", self.subscription_id)
        except Exception as exc:  # noqa: BLE001 - any auth failure means demo mode
            logger.info("No live Azure credentials available (%s) - using demo mode.", exc)
            self._credential = None
            self._live = False

    def _resolve_subscription_id(self, credential) -> str | None:
        if self.subscription_id:
            return self.subscription_id
        try:
            from azure.mgmt.resource import SubscriptionClient

            subs = list(SubscriptionClient(credential).subscriptions.list())
            if subs:
                return subs[0].subscription_id
        except Exception:  # noqa: BLE001
            logger.info("Could not list Azure subscriptions - using demo mode.")
        return None

    def client(self, kind: str):
        """Return a cached management client for `kind` (see _CLIENT_MODULES)."""
        if not self.is_live:
            raise RuntimeError("No live Azure session - cannot create a management client in demo mode.")
        if kind not in self._CLIENT_MODULES:
            raise ValueError(f"Unknown Azure client kind: {kind!r}")
        if kind not in self._clients:
            import importlib

            module_name, class_name = self._CLIENT_MODULES[kind]
            cls = getattr(importlib.import_module(module_name), class_name)
            if kind == "resource":
                self._clients[kind] = cls(self._credential)
            else:
                self._clients[kind] = cls(self._credential, self.subscription_id)
        return self._clients[kind]


class BaseScanner(ABC):
    """Abstract base for all resource scanners."""

    #: short, human-readable name used in logs / UI
    name: str = "base"
    #: cloud service this scanner targets, used for grouping in reports
    service: str = "generic"
    #: cloud provider this scanner targets ("aws" or "azure")
    provider: str = "aws"

    def __init__(self, session_manager: AWSSessionManager | AzureSessionManager) -> None:
        self.session_manager = session_manager

    @abstractmethod
    def run(self) -> list[Any]:
        """Execute all checks for this scanner and return Finding objects."""
        raise NotImplementedError

    def _demo_or_live(self, live_fn, demo_fn):
        """Helper: dispatch to live cloud calls or synthetic demo data."""
        if self.session_manager.is_live:
            try:
                return live_fn()
            except Exception:  # noqa: BLE001
                logger.exception("%s: live scan failed, falling back to demo data.", self.name)
                return demo_fn()
        return demo_fn()

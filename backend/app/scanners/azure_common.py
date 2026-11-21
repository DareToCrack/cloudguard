"""Shared helpers for the Azure scanner modules."""

from __future__ import annotations


def azure_resource_id(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    resource_type: str,
    name: str,
) -> str:
    """Build a canonical Azure resource ID.

    Example:
    ``/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/
    storageAccounts/<name>``
    """
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/{namespace}/{resource_type}/{name}"
    )


def resource_group_from_id(resource_id: str) -> str:
    """Extract the resource group name from an Azure resource ID."""
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return "unknown"


def subscription_scope(subscription_id: str) -> str:
    return f"/subscriptions/{subscription_id}"


def effective_subscription_id(session_manager) -> str:
    """Subscription ID to stamp on findings.

    In live mode this is the real subscription being scanned. In demo
    mode it is always the synthetic demo subscription ID - even if
    ``AZURE_SUBSCRIPTION_ID`` happens to be set in the environment
    without valid credentials, the demo inventory belongs to the demo
    subscription, so scope comparisons (e.g. "is this assignment at
    subscription scope?") must use the demo ID to match the demo data.
    """
    from app.scanners.azure_demo_data import DEMO_AZURE_SUBSCRIPTION_ID

    if getattr(session_manager, "is_live", False):
        return getattr(session_manager, "subscription_id", None) or DEMO_AZURE_SUBSCRIPTION_ID
    return DEMO_AZURE_SUBSCRIPTION_ID

"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanners.base import AWSSessionManager  # noqa: E402


class FakeDemoSessionManager(AWSSessionManager):
    """Forces demo-mode (is_live == False) regardless of environment,
    so unit tests never accidentally hit a real AWS account."""

    def __init__(self):
        super().__init__(profile=None, region="us-east-1")

    @property
    def is_live(self) -> bool:
        return False


@pytest.fixture
def demo_session():
    return FakeDemoSessionManager()

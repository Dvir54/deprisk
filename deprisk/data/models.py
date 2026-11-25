"""Data-layer types: raw PyPI facts and input requirements.

The record and snapshot types are added in M2 (PLAN.md "Shared interfaces").
"""

from __future__ import annotations


class FetchError(Exception):
    """A PyPI or top-list request failed after all retries."""


class SnapshotDataError(Exception):
    """Data needed for scoring is missing from the snapshot (never fetched silently)."""

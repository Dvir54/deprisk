"""Data-layer types: raw PyPI facts and input requirements (PLAN.md "Shared interfaces").

``None`` in metadata fields means "absent or null on PyPI" and is kept distinct from an
empty tuple, so missing metadata stays visible to scoring (SPEC §11).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from packaging.specifiers import SpecifierSet
from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    """Base of every deprisk data model: immutable, unknown fields rejected.

    ``arbitrary_types_allowed`` lets models hold ``packaging`` objects such as
    ``SpecifierSet``, which pydantic does not know natively.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)


class FetchError(Exception):
    """A PyPI or top-list request failed after all retries."""


class SnapshotDataError(Exception):
    """Data needed for scoring is missing from the snapshot (never fetched silently)."""


class FileInfo(FrozenModel):
    """One distribution file of a release."""

    filename: str
    packagetype: str  # "sdist", "bdist_wheel", "bdist_egg", ...
    upload_time: datetime
    yanked: bool
    requires_python: str | None


class Advisory(FrozenModel):
    """One entry of PyPI's ``vulnerabilities`` list (OSV-backed)."""

    id: str
    aliases: tuple[str, ...]
    fixed_in: tuple[str, ...]
    withdrawn: bool
    summary: str


class VersionMeta(FrozenModel):
    """Per-version metadata needed for scoring; ``None`` = absent/null, ``()`` = empty."""

    classifiers: tuple[str, ...] | None
    requires_dist: tuple[str, ...] | None
    vulnerabilities: tuple[Advisory, ...] | None


class PackageRecord(FrozenModel):
    """Compact per-package record (SPEC §9.2); ``releases`` maps version string -> files."""

    name: str
    last_serial: int
    fetched_at: datetime
    roles: tuple[tuple[str, str], ...]
    releases: Mapping[str, tuple[FileInfo, ...]]
    version_meta: Mapping[str, VersionMeta]
    version_fetched_at: Mapping[str, datetime]


class Snapshot(FrozenModel):
    """Frozen baseline data: run metadata, baseline names in rank order, records by name."""

    meta: Mapping[str, Any]
    baseline_names: tuple[str, ...]
    records: Mapping[str, PackageRecord]


class Requirement(FrozenModel):
    """One parsed requirements.txt entry (PEP 503-normalised name)."""

    name: str
    specifier: SpecifierSet
    line: str


class ParseIssue(FrozenModel):
    """A requirements.txt line that was not parsed (reported, never silently skipped)."""

    line_no: int
    line: str
    reason: str

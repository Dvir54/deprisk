"""Data-layer types: raw PyPI facts and input requirements (PLAN.md "Shared interfaces").

``None`` in metadata fields means "absent or null on PyPI" and is kept distinct from an
empty tuple, so missing metadata stays visible to scoring (SPEC §11).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from packaging.specifiers import SpecifierSet


class FetchError(Exception):
    """A PyPI or top-list request failed after all retries."""


class SnapshotDataError(Exception):
    """Data needed for scoring is missing from the snapshot (never fetched silently)."""


@dataclass(frozen=True)
class FileInfo:
    """One distribution file of a release."""

    filename: str
    packagetype: str  # "sdist", "bdist_wheel", "bdist_egg", ...
    upload_time: datetime
    yanked: bool
    requires_python: str | None


@dataclass(frozen=True)
class Advisory:
    """One entry of PyPI's ``vulnerabilities`` list (OSV-backed)."""

    id: str
    aliases: tuple[str, ...]
    fixed_in: tuple[str, ...]
    withdrawn: bool
    summary: str


@dataclass(frozen=True)
class VersionMeta:
    """Per-version metadata needed for scoring; ``None`` = absent/null, ``()`` = empty."""

    classifiers: tuple[str, ...] | None
    requires_dist: tuple[str, ...] | None
    vulnerabilities: tuple[Advisory, ...] | None


@dataclass(frozen=True)
class PackageRecord:
    """Compact per-package record (SPEC §9.2); ``releases`` maps version string -> files."""

    name: str
    last_serial: int
    fetched_at: datetime
    roles: tuple[tuple[str, str], ...]
    releases: Mapping[str, tuple[FileInfo, ...]]
    version_meta: Mapping[str, VersionMeta]
    version_fetched_at: Mapping[str, datetime]


@dataclass(frozen=True)
class Snapshot:
    """Frozen baseline data: run metadata, baseline names in rank order, records by name."""

    meta: Mapping[str, Any]
    baseline_names: tuple[str, ...]
    records: Mapping[str, PackageRecord]


@dataclass(frozen=True)
class Requirement:
    """One parsed requirements.txt entry (PEP 503-normalised name)."""

    name: str
    specifier: SpecifierSet
    line: str


@dataclass(frozen=True)
class ParseIssue:
    """A requirements.txt line that was not parsed (reported, never silently skipped)."""

    line_no: int
    line: str
    reason: str

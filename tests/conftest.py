"""Shared test helpers: a compact ``PackageRecord`` builder and a fixed reference time.

Tests run with ``--import-mode=importlib``, so helpers are exposed as fixtures
(``make_record`` returns the builder function) rather than imported from this module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from deprisk.data.models import Advisory, FileInfo, PackageRecord, VersionMeta

FIXED_T = datetime(2026, 11, 25, tzinfo=UTC)
DEFAULT_UPLOAD = datetime(2024, 1, 1, tzinfo=UTC)

RecordBuilder = Callable[..., PackageRecord]


def _as_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _file(name: str, version: str, spec: Mapping[str, Any]) -> FileInfo:
    packagetype = spec.get("packagetype", "sdist")
    default_name = (
        f"{name}-{version}.tar.gz"
        if packagetype == "sdist"
        else f"{name}-{version}-py3-none-any.whl"
    )
    return FileInfo(
        filename=spec.get("filename", default_name),
        packagetype=packagetype,
        upload_time=_as_datetime(spec.get("upload_time", DEFAULT_UPLOAD)),
        yanked=spec.get("yanked", False),
        requires_python=spec.get("requires_python"),
    )


def _advisory(entry: Advisory | Mapping[str, Any]) -> Advisory:
    if isinstance(entry, Advisory):
        return entry
    return Advisory(
        id=entry.get("id", "GHSA-test"),
        aliases=tuple(entry.get("aliases", ())),
        fixed_in=tuple(entry.get("fixed_in", ())),
        withdrawn=entry.get("withdrawn", False),
        summary=entry.get("summary", ""),
    )


def _meta(entry: VersionMeta | Mapping[str, Any]) -> VersionMeta:
    """Build VersionMeta from a dict; a missing key means absent/null (``None``)."""
    if isinstance(entry, VersionMeta):
        return entry
    vulns = entry.get("vulnerabilities")
    return VersionMeta(
        classifiers=None if entry.get("classifiers") is None else tuple(entry["classifiers"]),
        requires_dist=None if entry.get("requires_dist") is None else tuple(entry["requires_dist"]),
        vulnerabilities=None if vulns is None else tuple(_advisory(v) for v in vulns),
    )


def build_record(
    releases: Mapping[str, list[Mapping[str, Any]]],
    version_meta: Mapping[str, VersionMeta | Mapping[str, Any]] | None = None,
    name: str = "pkg",
) -> PackageRecord:
    """Build a record; each file dict may override ``filename``, ``packagetype``,
    ``upload_time``, ``yanked`` and ``requires_python`` (defaults: sdist uploaded
    2024-01-01, not yanked, ``requires_python=None``)."""
    metas = {v: _meta(m) for v, m in (version_meta or {}).items()}
    return PackageRecord(
        name=name,
        last_serial=1,
        fetched_at=FIXED_T,
        roles=(),
        releases={v: tuple(_file(name, v, f) for f in files) for v, files in releases.items()},
        version_meta=metas,
        version_fetched_at={v: FIXED_T for v in metas},
    )


@pytest.fixture
def make_record() -> RecordBuilder:
    """The ``build_record`` builder (PLAN.md Task 2.1)."""
    return build_record


@pytest.fixture
def fixed_t() -> datetime:
    """A fixed reference time ``T`` for deterministic tests."""
    return FIXED_T

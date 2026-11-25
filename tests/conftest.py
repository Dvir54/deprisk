"""Shared test helpers: a compact ``PackageRecord`` builder and a fixed reference time.

Tests run with ``--import-mode=importlib``, so helpers are exposed as fixtures
(``make_record`` returns the builder function) rather than imported from this module.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from deprisk.data.models import Advisory, FileInfo, PackageRecord, Snapshot, VersionMeta

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


def build_snapshot(
    records: Mapping[str, PackageRecord],
    exclusions: Mapping[str, str] | None = None,
    baseline_names: tuple[str, ...] | None = None,
    t: datetime = FIXED_T,
) -> Snapshot:
    """A snapshot over ``records`` (keyed by name); excluded names join the baseline list."""
    exclusions = dict(exclusions or {})
    names = baseline_names or (*records, *exclusions)
    meta = {
        "id": "test-snapshot",
        "T": t.isoformat(),
        "top_list": {"last_update": "2026-11-01 06:41:05", "fetched_at": t.isoformat()},
        "baseline": {"definition": "test baseline", "n_requested": len(names)},
        "config_hash": "test",
        "exclusions": exclusions,
    }
    return Snapshot(meta=meta, baseline_names=tuple(names), records=dict(records))


@pytest.fixture
def make_snapshot() -> Callable[..., Snapshot]:
    """The ``build_snapshot`` builder: a Snapshot with test metadata and ``T``."""
    return build_snapshot


@pytest.fixture
def make_record() -> RecordBuilder:
    """The ``build_record`` builder (PLAN.md Task 2.1)."""
    return build_record


@pytest.fixture
def fixed_t() -> datetime:
    """A fixed reference time ``T`` for deterministic tests."""
    return FIXED_T


_CLEAN = {"classifiers": [], "requires_dist": [], "vulnerabilities": []}


def build_mini_snapshot() -> Snapshot:
    """Nine synthetic packages covering the main cases, plus one build-time exclusion.

    fresh0-4: maintained pure-Python wheels with 0-4 dependencies; legacy: sdist only,
    stale classifiers, unknown dependencies, an unfixed advisory; fallback: the latest
    release excludes 3.12 (pip falls back to 1.0); beta: only pre-releases (unscored);
    gone: excluded when the snapshot was built ("data unavailable").
    """
    recs: dict[str, PackageRecord] = {}
    for i in range(5):
        upload = datetime(2026, 11 - 2 * i, 1, tzinfo=UTC).isoformat()
        wheel = {
            "packagetype": "bdist_wheel",
            "filename": f"fresh{i}-1.{i}-py3-none-any.whl",
            "upload_time": upload,
            "requires_python": ">=3.9",
        }
        meta = {
            **_CLEAN,
            "classifiers": ["Programming Language :: Python :: 3.12"],
            "requires_dist": [f"dep{j}" for j in range(i)],
        }
        recs[f"fresh{i}"] = build_record({f"1.{i}": [wheel]}, {f"1.{i}": meta}, name=f"fresh{i}")
    recs["legacy"] = build_record(
        {"2.6": [{"upload_time": "2014-06-20T00:00:00+00:00"}]},
        {
            "2.6": {
                "classifiers": ["Programming Language :: Python :: 3.4"],
                "requires_dist": None,
                "vulnerabilities": [{"id": "PYSEC-1", "aliases": ["CVE-2013-1"], "fixed_in": []}],
            }
        },
        name="legacy",
    )
    recs["fallback"] = build_record(
        {
            "1.0": [{"upload_time": "2019-01-01T00:00:00+00:00"}],
            "2.0": [{"upload_time": "2021-01-01T00:00:00+00:00", "requires_python": ">=3.13"}],
        },
        {"1.0": _CLEAN, "2.0": _CLEAN},
        name="fallback",
    )
    recs["beta"] = build_record({"1.0b1": [{}]}, name="beta")
    return build_snapshot(recs, exclusions={"gone": "data unavailable"})


@pytest.fixture
def mini_snapshot() -> Snapshot:
    """A small synthetic snapshot (see ``build_mini_snapshot``)."""
    return build_mini_snapshot()


@pytest.fixture
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any outgoing socket connection fail, so a test proves it works offline."""

    def refuse(*_: object, **__: object) -> None:
        raise OSError("network access is blocked in this test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)

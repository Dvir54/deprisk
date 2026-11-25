"""Compact per-package records extracted from PyPI JSON (SPEC §9.2, §11).

Only the fields scoring needs are kept; free text (author, description, ...) is dropped.
Metadata that is absent, ``null`` or not a list becomes ``None`` ("unknown"), kept
distinct from an empty list. Malformed entries are kept in their riskier reading.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from packaging.utils import canonicalize_name

from deprisk import config
from deprisk.data.models import Advisory, FileInfo, PackageRecord, VersionMeta

log = logging.getLogger(__name__)


def _parse_time(value: Any) -> datetime | None:
    """ISO-8601 timestamp as an aware UTC datetime; None if it cannot be parsed."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _str_tuple(value: Any) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _withdrawn(value: Any) -> bool:
    """OSV ``withdrawn`` is null or a timestamp; anything unparseable reads as not withdrawn."""
    if isinstance(value, bool):
        return value
    return _parse_time(value) is not None


def _advisory(entry: Any) -> Advisory:
    """One advisory; a broken entry is kept with ``id="unknown"`` (it still counts for S6)."""
    if not isinstance(entry, Mapping):
        entry = {}
    adv_id = entry.get("id")
    text = entry.get("summary") or entry.get("details")
    return Advisory(
        id=adv_id if isinstance(adv_id, str) and adv_id else "unknown",
        aliases=_str_tuple(entry.get("aliases")),
        fixed_in=_str_tuple(entry.get("fixed_in")),
        withdrawn=_withdrawn(entry.get("withdrawn")),
        summary=text[: config.ADVISORY_SUMMARY_CHARS] if isinstance(text, str) else "",
    )


def _version_meta(info: Mapping[str, Any], vulnerabilities: Any) -> VersionMeta:
    classifiers = info.get("classifiers")
    requires_dist = info.get("requires_dist")
    return VersionMeta(
        # Non-string classifiers are dropped (they could only add positive evidence);
        # non-string requires_dist entries are kept as text so S7 counts them as malformed.
        classifiers=_str_tuple(classifiers) if isinstance(classifiers, list) else None,
        requires_dist=tuple(str(r) for r in requires_dist)
        if isinstance(requires_dist, list)
        else None,
        vulnerabilities=tuple(_advisory(v) for v in vulnerabilities)
        if isinstance(vulnerabilities, list)
        else None,
    )


def _files(name: str, version: str, raw_files: Any) -> tuple[FileInfo, ...]:
    files: list[FileInfo] = []
    for raw in raw_files if isinstance(raw_files, list) else []:
        upload = _parse_time(raw.get("upload_time_iso_8601")) if isinstance(raw, Mapping) else None
        if upload is None:
            log.warning("%s %s: dropped a file with no parseable upload time", name, version)
            continue
        requires_python = raw.get("requires_python")
        files.append(
            FileInfo(
                filename=str(raw.get("filename", "")),
                packagetype=str(raw.get("packagetype", "")),
                upload_time=upload,
                yanked=raw.get("yanked") is True,
                requires_python=requires_python if isinstance(requires_python, str) else None,
            )
        )
    return tuple(files)


def _roles(ownership: Any) -> tuple[tuple[str, str], ...]:
    roles = ownership.get("roles") if isinstance(ownership, Mapping) else None
    pairs = {
        (r["role"], r["user"])
        for r in roles or []
        if isinstance(r, Mapping)
        and isinstance(r.get("role"), str)
        and isinstance(r.get("user"), str)
    }
    return tuple(sorted(pairs))


def extract_record(project_json: Mapping[str, Any], fetched_at: datetime) -> PackageRecord:
    """Compact record from ``/pypi/<name>/json``; the latest version's metadata is included."""
    info = project_json.get("info") or {}
    name = canonicalize_name(str(info.get("name", "")))
    releases = project_json.get("releases") or {}
    version_meta: dict[str, VersionMeta] = {}
    version_fetched_at: dict[str, datetime] = {}
    latest = info.get("version")
    if isinstance(latest, str) and latest:
        version_meta[latest] = _version_meta(info, project_json.get("vulnerabilities"))
        version_fetched_at[latest] = fetched_at
    return PackageRecord(
        name=name,
        last_serial=int(project_json.get("last_serial") or 0),
        fetched_at=fetched_at,
        roles=_roles(project_json.get("ownership")),
        releases={v: _files(name, v, files) for v, files in releases.items()},
        version_meta=version_meta,
        version_fetched_at=version_fetched_at,
    )


def add_version_meta(
    record: PackageRecord, version: str, version_json: Mapping[str, Any], fetched_at: datetime
) -> PackageRecord:
    """A copy of ``record`` with metadata from ``/pypi/<name>/<version>/json`` added."""
    meta = _version_meta(version_json.get("info") or {}, version_json.get("vulnerabilities"))
    return record.model_copy(
        update={
            "version_meta": {**record.version_meta, version: meta},
            "version_fetched_at": {**record.version_fetched_at, version: fetched_at},
        }
    )


def as_of(record: PackageRecord, t: datetime) -> PackageRecord:
    """The record as it looked at ``t``: files uploaded after ``t`` are dropped.

    A release whose files were all uploaded after ``t`` disappears; a release that never
    had files is kept unchanged. Metadata still reflects fetch time (SPEC §13).
    """
    releases: dict[str, tuple[FileInfo, ...]] = {}
    for version, files in record.releases.items():
        kept = tuple(f for f in files if f.upload_time <= t)
        if kept or not files:
            releases[version] = kept
    return record.model_copy(update={"releases": releases})

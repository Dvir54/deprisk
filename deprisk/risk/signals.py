"""Raw signal values of one package at ``T`` (SPEC §8, §11).

Scored: S1, S2 (whole project), S4, S5 (versions module), S6, S7 (reference version).
Evidence only: S3, S8, S9, S10, S14. Unknown values are ``None`` and listed under
``evidence["missing"]``; malformed ``requires_dist`` entries count as dependencies
(they cannot be shown not to apply) and mark S7 as ``partial`` (a lower bound).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from packaging.markers import InvalidMarker, UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from deprisk import config
from deprisk.data.models import PackageRecord, SnapshotDataError, VersionMeta
from deprisk.risk import versions
from deprisk.risk.environment import marker_applies
from deprisk.risk.models import PackageSignals

INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"
_SECONDS_PER_DAY = 86400.0


def _days(earlier: datetime, t: datetime) -> float:
    return (t - earlier).total_seconds() / _SECONDS_PER_DAY


def _dependencies(requires_dist: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """Distinct normalised names of entries that apply on the target env, and malformed entries."""
    names: set[str] = set()
    malformed: list[str] = []
    for entry in requires_dist:
        try:
            req = Requirement(entry)
            applies = req.marker is None or marker_applies(req.marker)
        except (InvalidRequirement, InvalidMarker, UndefinedComparison, UndefinedEnvironmentName):
            malformed.append(entry)
            continue
        if applies:
            names.add(canonicalize_name(req.name))
    return sorted(names), malformed


def _releases_in_window(record: PackageRecord, t: datetime) -> int:
    """S2: final releases whose release date (earliest non-yanked upload) is in the window."""
    start = t - timedelta(days=config.S2_WINDOW_DAYS)
    count = 0
    for _, raw in versions.parse_final_versions(record.releases):
        released = versions.release_date(record.releases[raw])
        if released is not None and start <= released <= t:
            count += 1
    return count


def _yanked_release_share(record: PackageRecord) -> float:
    """S9: share of releases with files whose files are all yanked."""
    with_files = [files for files in record.releases.values() if files]
    if not with_files:
        return 0.0
    return sum(all(f.yanked for f in files) for files in with_files) / len(with_files)


def compute_signals(record: PackageRecord, spec: SpecifierSet, t: datetime) -> PackageSignals:
    """All signal values for ``record`` under ``spec`` at ``t``.

    Raises UnscorableError (no reference version) or SnapshotDataError (the reference
    version's metadata is not in the snapshot).
    """
    effective = versions.effective_version(record, spec)
    reference = versions.reference_version(record, spec)
    meta: VersionMeta | None = record.version_meta.get(reference)
    if meta is None:
        raise SnapshotDataError(f"{record.name}: no metadata for reference version {reference}")

    uploads = [f.upload_time for files in record.releases.values() for f in files if not f.yanked]
    last_upload = max(uploads)  # a reference version guarantees a non-yanked file
    missing: list[str] = []

    s6: float | None = None
    advisories: list[dict[str, Any]] = []
    if meta.vulnerabilities is None:
        missing.append("vulnerabilities")
    else:
        advisories = [
            {"id": a.id, "aliases": list(a.aliases), "fixed_in": list(a.fixed_in)}
            for a in meta.vulnerabilities
            if not a.withdrawn
        ]
        s6 = len(advisories)

    s7: float | None = None
    dependencies: list[str] = []
    malformed: list[str] = []
    if meta.requires_dist is None:
        missing.append("requires_dist")
    else:
        dependencies, malformed = _dependencies(meta.requires_dist)
        s7 = len(dependencies) + len(malformed)

    effective_released = (
        versions.release_date(record.releases[effective]) if effective is not None else None
    )
    evidence: dict[str, Any] = {
        "specifier": str(spec),
        "last_upload": last_upload.isoformat(),
        "missing": missing,
        "advisories": advisories,
        "dependencies": dependencies,
        "malformed_requires_dist": malformed,
        "skipped_versions": versions.count_skipped_versions(record.releases),
        "S3": _days(effective_released, t) if effective_released is not None else None,
        "S8": len({user for _, user in record.roles}),
        "S9": _yanked_release_share(record),
        "S10": Version(reference).major == 0,
        "S14": INACTIVE_CLASSIFIER in (meta.classifiers or ()),
    }
    values: dict[str, float | None] = {
        "S1": _days(last_upload, t),
        "S2": _releases_in_window(record, t),
        "S4": versions.py312_evidence_state(
            record, spec, effective, meta if effective is not None else None
        ),
        "S5": versions.install_path_state(record, effective),
        "S6": s6,
        "S7": s7,
    }
    return PackageSignals(
        name=record.name,
        effective_version=effective,
        reference_version=reference,
        values=values,
        partial=frozenset({"S7"}) if malformed else frozenset(),
        evidence=evidence,
    )

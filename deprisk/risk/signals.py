"""Raw signal values of one package at ``T`` (SPEC §8, §11).

Scored: S1, S2 (whole project), S4, S5 (versions module), S6, S7 (reference version).
Evidence only: S3, S8, S9, S10, S14. Unknown values are ``None`` and listed under
``evidence["missing"]``; malformed ``requires_dist`` entries count as dependencies
(they cannot be shown not to apply) and mark S7 as ``partial`` (a lower bound).
S6 counts distinct vulnerabilities: PyPI lists one vulnerability under several advisory
ids (e.g. PYSEC and GHSA), so entries linked by a shared id or alias count once.
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


UNKNOWN_ADVISORY_ID = "unknown"  # set by records.extract_record for a malformed entry


def group_advisories(advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge advisory entries that describe the same vulnerability.

    Two entries are linked when their identifier sets (``id`` plus ``aliases``) share a
    value; links are transitive (union-find), so A-B and B-C make one group. The
    placeholder id "unknown" links nothing, so malformed entries still count on their
    own (the riskier reading). Each group lists its sorted ids, the aliases that are not
    member ids, and the union of the members' ``fixed_in``. Groups are sorted by ids.
    """
    parent = list(range(len(advisories)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, adv in enumerate(advisories):
        for ident in {adv["id"], *adv["aliases"]} - {UNKNOWN_ADVISORY_ID}:
            if ident in owner:
                parent[root(i)] = root(owner[ident])
            else:
                owner[ident] = i

    members: dict[int, list[dict[str, Any]]] = {}
    for i, adv in enumerate(advisories):
        members.setdefault(root(i), []).append(adv)
    groups = []
    for entries in members.values():
        ids = sorted({a["id"] for a in entries})
        aliases = sorted({alias for a in entries for alias in a["aliases"]} - set(ids))
        fixed_in = sorted({v for a in entries for v in a["fixed_in"]})
        groups.append({"ids": ids, "aliases": aliases, "fixed_in": fixed_in})
    return sorted(groups, key=lambda g: g["ids"])


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
    advisory_groups: list[dict[str, Any]] = []
    if meta.vulnerabilities is None:
        missing.append("vulnerabilities")
    else:
        advisories = [  # the original PyPI entries, kept as evidence
            {"id": a.id, "aliases": list(a.aliases), "fixed_in": list(a.fixed_in)}
            for a in meta.vulnerabilities
            if not a.withdrawn
        ]
        advisory_groups = group_advisories(advisories)
        s6 = len(advisory_groups)

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
        "advisory_groups": advisory_groups,
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

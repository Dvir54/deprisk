"""Version logic for the target environment: eligibility, effective/reference versions,
and the S4/S5 ordinal states (SPEC §11, §12.2, §12.3).

Metadata eligibility only: what pip would select, not proof that a package builds or runs.
Malformed inputs never make a package look safer: invalid versions are skipped, an invalid
``requires_python`` does not admit the target, and an unparseable wheel name is ineligible.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from deprisk import config
from deprisk.data.models import FileInfo, PackageRecord, VersionMeta
from deprisk.risk.environment import ACCEPTED_TAGS
from deprisk.risk.models import UnscorableError

Releases = Mapping[str, tuple[FileInfo, ...]]

_TARGET_PYTHON = Version(config.PYTHON_FULL_VERSION)
_TARGET_INTERPRETER = f"cp{config.PYTHON_VERSION[0]}{config.PYTHON_VERSION[1]}"
_PY3_MINOR_CLASSIFIER = re.compile(r"^Programming Language :: Python :: 3\.(\d+)$")


def _parse(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def parse_final_versions(releases: Releases) -> list[tuple[Version, str]]:
    """Valid final (non-pre, non-dev) versions, highest first; others are skipped."""
    finals = [(v, s) for s in releases if (v := _parse(s)) is not None and not v.is_prerelease]
    return sorted(finals, reverse=True)


def count_skipped_versions(releases: Releases) -> dict[str, int]:
    """How many release keys ``parse_final_versions`` skipped, by reason (for evidence)."""
    parsed = [_parse(s) for s in releases]
    return {
        "invalid": sum(v is None for v in parsed),
        "prerelease": sum(v is not None and v.is_prerelease for v in parsed),
    }


def file_admits_target(f: FileInfo) -> bool:
    """Whether the file's ``requires_python`` admits the target Python.

    Unspecified (``None`` or blank) admits it, as in pip. An invalid specifier does not:
    the riskier reading, since it cannot be shown to admit 3.12.
    """
    if f.requires_python is None or not f.requires_python.strip():
        return True
    try:
        spec = SpecifierSet(f.requires_python)
    except InvalidSpecifier:
        return False
    return spec.contains(_TARGET_PYTHON, prereleases=True)


def _wheel_tags(f: FileInfo) -> frozenset:
    """Tags of a wheel file; empty for non-wheels and unparseable wheel names."""
    if f.packagetype != "bdist_wheel":
        return frozenset()
    try:
        return parse_wheel_filename(f.filename)[3]
    except InvalidWheelFilename:
        return frozenset()


def _is_eligible_wheel(f: FileInfo) -> bool:
    return not f.yanked and file_admits_target(f) and bool(_wheel_tags(f) & ACCEPTED_TAGS)


def file_is_eligible(f: FileInfo) -> bool:
    """Not yanked, admits the target, and an sdist or a wheel with an accepted tag.

    Eggs and other legacy formats are never eligible (modern pip does not install them).
    """
    if f.yanked or not file_admits_target(f):
        return False
    return f.packagetype == "sdist" or _is_eligible_wheel(f)


def _has_unyanked_file(files: Iterable[FileInfo]) -> bool:
    return any(not f.yanked for f in files)


def effective_version(record: PackageRecord, spec: SpecifierSet) -> str | None:
    """Highest final release in ``spec`` with an eligible file (SPEC §12.2), else None."""
    for version, raw in parse_final_versions(record.releases):
        if spec.contains(version) and any(file_is_eligible(f) for f in record.releases[raw]):
            return raw
    return None


def reference_version(record: PackageRecord, spec: SpecifierSet) -> str:
    """The version S4/S6/S7 are measured on (SPEC §11).

    The effective version if one exists, otherwise the newest final release with a
    non-yanked file. Raises UnscorableError with the reason when there is none.
    """
    effective = effective_version(record, spec)
    if effective is not None:
        return effective
    finals = parse_final_versions(record.releases)
    for _, raw in finals:
        if _has_unyanked_file(record.releases[raw]):
            return raw
    with_files = [s for s, files in record.releases.items() if files]
    if not with_files:
        raise UnscorableError("no files")
    valid = [v for s in with_files if (v := _parse(s)) is not None]
    if not valid:
        raise UnscorableError("no valid versions")
    if all(v.is_prerelease for v in valid):
        raise UnscorableError("only pre-releases")
    raise UnscorableError("only yanked files")


def install_path_state(record: PackageRecord, effective: str | None) -> int:
    """S5: 0 = eligible wheel, 1 = sdist only (build required), 2 = no effective version."""
    if effective is None:
        return 2
    if any(_is_eligible_wheel(f) for f in record.releases[effective]):
        return 0
    return 1


def _py3_minors(meta: VersionMeta | None) -> list[int]:
    """Python 3 minor versions named by ``Programming Language :: Python :: 3.N`` classifiers."""
    if meta is None or not meta.classifiers:
        return []
    return [
        int(m.group(1)) for c in meta.classifiers if (m := _PY3_MINOR_CLASSIFIER.match(c.strip()))
    ]


def _has_newer_installable_release(
    record: PackageRecord, spec: SpecifierSet, effective: str
) -> bool:
    """A final release above E that ``spec`` allows and that has a non-yanked file."""
    floor = Version(effective)
    return any(
        version > floor and spec.contains(version) and _has_unyanked_file(record.releases[raw])
        for version, raw in parse_final_versions(record.releases)
    )


def py312_evidence_state(
    record: PackageRecord,
    spec: SpecifierSet,
    effective: str | None,
    meta: VersionMeta | None,
) -> int:
    """S4 Python 3.12 evidence state, first matching rule of SPEC §12.3.

    ``meta`` is the version metadata of the effective version (``None`` if absent).
    """
    if effective is None:
        return 5
    if _has_newer_installable_release(record, spec, effective):
        return 4
    eligible = [f for f in record.releases[effective] if file_is_eligible(f)]
    minors = _py3_minors(meta)
    cp312_wheel = any(
        any(tag.interpreter == _TARGET_INTERPRETER for tag in _wheel_tags(f) & ACCEPTED_TAGS)
        for f in eligible
    )
    if any(n >= config.PYTHON_VERSION[1] for n in minors) or cp312_wheel:
        return 0
    if any(f.requires_python and f.requires_python.strip() for f in eligible):
        return 1
    if minors:
        return 3
    return 2


def release_date(files: Iterable[FileInfo]) -> datetime | None:
    """Earliest non-yanked upload time of a release, or None if it has none."""
    times = [f.upload_time for f in files if not f.yanked]
    return min(times) if times else None

"""Read-only agent tools (SPEC §13) and evidence collection for the validator (§15).

Every tool reads the frozen snapshot first and fetches live PyPI data only for what the
snapshot lacks (a version's metadata, a replacement candidate). Outputs hold structured
fields only, never descriptions. Every call, including a failed one, is appended to
``AgentTools.log`` with its data source, origin and fetch time; a failure becomes an
``{"error": ...}`` output instead of an exception, so one bad tool input never ends a run.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Literal

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from deprisk import config
from deprisk.agent.models import ToolCall, ValidationContext
from deprisk.agent.validator import highest_allowed_below, parse_bound
from deprisk.data.models import FileInfo, PackageRecord, Requirement, Snapshot, VersionMeta
from deprisk.data.records import add_version_meta, as_of, extract_record
from deprisk.risk import versions
from deprisk.risk.models import Baseline, UnscorableError
from deprisk.risk.scoring import score_package
from deprisk.risk.signals import compute_signals

log = logging.getLogger(__name__)

Fetched = tuple[dict[str, Any], datetime]
FetchLive = Callable[[str, str | None], Fetched | None]
Source = Literal["snapshot", "live", "local"]
Result = tuple[dict[str, Any], Source, datetime | None]

# PEP 508 project name (the replacement a candidate lookup may fetch).
_PROJECT_NAME = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)


class ToolError(Exception):
    """A tool input that names nothing real; returned to the agent as an error output."""


def _schema(name: str, description: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": sorted(properties),
            "additionalProperties": False,
        },
        "strict": True,
    }


_STRING = {"type": "string"}
TOOL_SCHEMAS: list[dict[str, Any]] = [
    _schema(
        "get_package_profile",
        "The package's deterministic risk profile: score, total, per-signal values and "
        "contributions, flags and evidence-only signals.",
        {},
    ),
    _schema(
        "get_release_history",
        "The package's newest releases (version, release date, pre-release, yanked) and totals.",
        {},
    ),
    _schema(
        "get_version_details",
        "One release of the package: final or not, yanked, eligible on CPython 3.12 Linux "
        "x86_64, allowed by the current specifier, files, requires_python, requires_dist "
        "and non-withdrawn vulnerabilities.",
        {"version": {**_STRING, "description": "A release version string, e.g. 2.0.1"}},
    ),
    _schema(
        "find_eligible_versions",
        "Every final release with a non-yanked file: whether the current specifier allows "
        "it and whether it is eligible on the target environment.",
        {},
    ),
    _schema(
        "lookup_candidate",
        "A possible replacement: whether it is a Python 3.12 stdlib module, whether it "
        "exists on PyPI, and its score against the same frozen baseline as of T.",
        {"name": {**_STRING, "description": "A PyPI project name or a stdlib module name"}},
    ),
    _schema(
        "get_requirement",
        "The package's requirement line and its context: the oldest allowed version, its "
        "vulnerabilities, and whether the specifier spans a major version or allows "
        "versions with advisories.",
        {},
    ),
]
_ARGS = {s["name"]: set(s["input_schema"]["properties"]) for s in TOOL_SCHEMAS}


def _parse(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _vulnerabilities(meta: VersionMeta | None) -> list[dict[str, Any]] | None:
    """Non-withdrawn advisories as ``{id, aliases, fixed_in}``; None when unknown."""
    if meta is None or meta.vulnerabilities is None:
        return None
    return [
        {"id": a.id, "aliases": list(a.aliases), "fixed_in": list(a.fixed_in)}
        for a in meta.vulnerabilities
        if not a.withdrawn
    ]


def _installable(record: PackageRecord) -> list[tuple[Version, str]]:
    """Final releases with at least one non-yanked file, highest first."""
    return [
        (v, raw)
        for v, raw in versions.parse_final_versions(record.releases)
        if any(not f.yanked for f in record.releases[raw])
    ]


class AgentTools:
    """The agent's read-only tools over one frozen snapshot, with a call log."""

    def __init__(
        self,
        snapshot: Snapshot,
        baseline: Baseline,
        profiles: Mapping[str, dict[str, Any]],
        requirements: Mapping[str, Requirement],
        fetch_live: FetchLive,
    ) -> None:
        self.snapshot = snapshot
        self.baseline = baseline
        self.profiles = profiles
        self.requirements = requirements
        self.fetch_live = fetch_live
        self.t = datetime.fromisoformat(snapshot.meta["T"])
        self.log: list[ToolCall] = []
        self._tools: dict[str, Callable[..., Result]] = {
            "get_package_profile": self._profile,
            "get_release_history": self._history,
            "get_version_details": self._version_details,
            "find_eligible_versions": self._eligible_versions,
            "lookup_candidate": self._lookup_candidate,
            "get_requirement": self._requirement,
        }

    # --- dispatch -------------------------------------------------------------------

    def call(
        self,
        package: str,
        name: str,
        args: Mapping[str, Any],
        origin: Literal["agent", "validation"] = "agent",
    ) -> ToolCall:
        """Run one tool for ``package`` and log it; failures become ``{"error": ...}``."""
        source: Source = "local"
        fetched_at: datetime | None = None
        try:
            if name not in self._tools:
                raise ToolError(f"unknown tool {name!r}")
            if set(args) != _ARGS[name] or not all(isinstance(v, str) for v in args.values()):
                expected = ", ".join(sorted(_ARGS[name])) or "none"
                raise ToolError(f"{name} takes exactly these string arguments: {expected}")
            output, source, fetched_at = self._tools[name](package, **args)
        except ToolError as exc:
            output = {"error": str(exc)}
        except Exception as exc:  # a tool failure must never end the agent run
            log.warning("tool %s for %s failed: %r", name, package, exc)
            output = {"error": f"{type(exc).__name__}: {exc}"}
            source, fetched_at = "local", None
        call = ToolCall(
            id=f"call_{len(self.log) + 1}",
            package=package,
            name=name,
            args=dict(args),
            output=output,
            source=source,
            origin=origin,
            fetched_at=fetched_at,
        )
        self.log.append(call)
        return call

    def collect_validation_evidence(
        self, package: str, rec: Mapping[str, Any]
    ) -> ValidationContext:
        """Log the facts the validator needs about the submitted action, then bundle them
        with the agent's own calls for ``package``.

        ``upgrade``/``pin``: find_eligible_versions, then get_version_details of V (for
        ``<V`` the highest allowed version below V). ``replace`` with a PyPI project:
        lookup_candidate. A stdlib replacement and ``do_nothing`` need no call. A target
        that cannot be parsed collects nothing; the validator reports it.
        """
        agent_calls = [c for c in self.log if c.package == package and c.origin == "agent"]
        calls: list[ToolCall] = []
        action = rec.get("action")
        target = str(rec.get("target") or "").strip()
        if action in ("upgrade", "pin") and (bound := parse_bound(target)) is not None:
            op, version = bound
            eligible = self.call(package, "find_eligible_versions", {}, origin="validation")
            calls.append(eligible)
            if op == "<":
                below = highest_allowed_below(eligible.output, version)
                version = below if below is not None else ""
            if version and "error" not in eligible.output:
                calls.append(
                    self.call(
                        package, "get_version_details", {"version": version}, origin="validation"
                    )
                )
        elif action == "replace" and rec.get("replacement_type") == "pypi" and target:
            calls.append(self.call(package, "lookup_candidate", {"name": target}, "validation"))
        req = self.requirements.get(package)
        return ValidationContext(
            package=package,
            profile=self.profiles.get(package, {}),
            specifier=str(req.specifier) if req is not None else "",
            calls=tuple(agent_calls + calls),
            t=self.t,
        )

    # --- helpers --------------------------------------------------------------------

    def _record(self, package: str) -> PackageRecord:
        record = self.snapshot.records.get(package)
        if record is None:
            raise ToolError(f"package {package!r} is not in the snapshot")
        return record

    def _requirement_of(self, package: str) -> Requirement:
        req = self.requirements.get(package)
        if req is None:
            raise ToolError(f"package {package!r} is not in the requirements file")
        return req

    def _version_meta(
        self, record: PackageRecord, version: str
    ) -> tuple[VersionMeta | None, Source, datetime | None]:
        """A version's metadata with its source: the snapshot first, else a live fetch."""
        if version in record.version_meta:
            fetched_at = record.version_fetched_at.get(version, record.fetched_at)
            return record.version_meta[version], "snapshot", fetched_at
        fetched = self.fetch_live(record.name, version)
        if fetched is None:  # unknown metadata stays unknown (shown as null)
            return None, "snapshot", record.fetched_at
        body, fetched_at = fetched
        updated = add_version_meta(record, version, body, fetched_at)
        return updated.version_meta[version], "live", fetched_at

    # --- tools ----------------------------------------------------------------------

    def _profile(self, package: str) -> Result:
        profile = self.profiles.get(package)
        if profile is None:
            raise ToolError(f"no profile for package {package!r}")
        record = self.snapshot.records.get(package)
        return dict(profile), "snapshot", record.fetched_at if record else None

    def _history(self, package: str) -> Result:
        record = self._record(package)
        parsed = sorted(
            ((v, raw) for raw in record.releases if (v := _parse(raw)) is not None), reverse=True
        )
        limit = config.HISTORY_LIMIT
        releases = [
            {
                "version": raw,
                "release_date": _iso(versions.release_date(record.releases[raw])),
                "prerelease": v.is_prerelease,
                "yanked": bool(record.releases[raw])
                and all(f.yanked for f in record.releases[raw]),
                "files": len(record.releases[raw]),
            }
            for v, raw in parsed[:limit]
        ]
        files = record.releases.values()
        totals = {
            "releases": len(record.releases),
            "final": sum(not v.is_prerelease for v, _ in parsed),
            "prerelease": sum(v.is_prerelease for v, _ in parsed),
            "invalid_versions": len(record.releases) - len(parsed),
            "yanked": sum(bool(fs) and all(f.yanked for f in fs) for fs in files),
            "without_files": sum(not fs for fs in files),
        }
        output = {"releases": releases, "totals": totals, "truncated": len(parsed) > limit}
        return output, "snapshot", record.fetched_at

    def _version_details(self, package: str, version: str) -> Result:
        record = self._record(package)
        raw = self._find_release(record, version)
        files: tuple[FileInfo, ...] = record.releases[raw]
        meta, source, fetched_at = self._version_meta(record, raw)
        parsed = _parse(raw)
        req = self.requirements.get(package)
        eligible = [f for f in files if versions.file_is_eligible(f)]
        output = {
            "version": raw,
            "is_final": parsed is not None and not parsed.is_prerelease,
            "yanked": bool(files) and all(f.yanked for f in files),
            "satisfies_specifier": None
            if req is None
            else parsed is not None and req.specifier.contains(parsed),
            "eligible": bool(eligible),
            "release_date": _iso(versions.release_date(files)),
            "requires_python": sorted({f.requires_python for f in files if f.requires_python}),
            "files": {
                "total": len(files),
                "yanked": sum(f.yanked for f in files),
                "sdists": sum(f.packagetype == "sdist" for f in files),
                "wheels": sum(f.packagetype == "bdist_wheel" for f in files),
                "other": sum(f.packagetype not in ("sdist", "bdist_wheel") for f in files),
            },
            "eligible_files": sorted(f.filename for f in eligible),
            "classifiers": None
            if meta is None or meta.classifiers is None
            else list(meta.classifiers),
            "requires_dist": None
            if meta is None or meta.requires_dist is None
            else list(meta.requires_dist),
            "vulnerabilities": _vulnerabilities(meta),
        }
        return output, source, fetched_at

    @staticmethod
    def _find_release(record: PackageRecord, version: str) -> str:
        if version in record.releases:
            return version
        wanted = _parse(version)
        for raw in record.releases:
            if wanted is not None and _parse(raw) == wanted:
                return raw
        raise ToolError(f"{record.name} has no release {version!r} (as of the snapshot)")

    def _eligible_versions(self, package: str) -> Result:
        record = self._record(package)
        spec = self._requirement_of(package).specifier
        listed = [
            {
                "version": raw,
                "allowed": spec.contains(v),
                "eligible": any(versions.file_is_eligible(f) for f in record.releases[raw]),
            }
            for v, raw in _installable(record)
        ]
        allowed = [e["version"] for e in listed if e["allowed"]]
        output = {
            "specifier": str(spec),
            "effective_version": versions.effective_version(record, spec),
            "oldest_allowed_version": allowed[-1] if allowed else None,
            "versions": listed,
        }
        return output, "snapshot", record.fetched_at

    def _requirement(self, package: str) -> Result:
        record = self._record(package)
        req = self._requirement_of(package)
        allowed = [(v, raw) for v, raw in _installable(record) if req.specifier.contains(v)]
        floor = allowed[-1][1] if allowed else None
        source: Source = "snapshot"
        fetched_at: datetime | None = record.fetched_at
        floor_vulns: list[dict[str, Any]] | None = []
        if floor is not None:
            meta, source, fetched_at = self._version_meta(record, floor)
            floor_vulns = _vulnerabilities(meta)
        majors = sorted({v.major for v, _ in allowed})
        output = {
            "specifier": str(req.specifier),
            "line": req.line,
            "allowed_versions": len(allowed),
            "floor_version": floor,
            "allowed_majors": majors,
            "spec_spans_major": len(majors) > 1,
            "floor_vulnerabilities": floor_vulns,
            "spec_allows_advisories": None if floor_vulns is None else bool(floor_vulns),
        }
        return output, source, fetched_at

    def _lookup_candidate(self, package: str, name: str) -> Result:
        name = name.strip()
        output: dict[str, Any] = {
            "name": name,
            "is_stdlib_module": name.split(".")[0] in sys.stdlib_module_names,
            "exists": False,
            "in_snapshot": False,
            "valid": False,
            "reason": None,
            "effective_version": None,
            "reference_version": None,
            "final_score": None,
            "total": None,
            "values": None,
            "flags": [],
            "beyond_baseline_range": [],
        }
        if not _PROJECT_NAME.match(name):
            output["reason"] = "not a valid PyPI project name"
            return output, "local", None
        canonical = canonicalize_name(name)
        output["name"] = canonical
        record = self.snapshot.records.get(canonical)
        source: Source = "snapshot"
        if record is None:
            source = "live"
            fetched = self.fetch_live(canonical, None)
            if fetched is None:
                output["reason"] = "not found on PyPI"
                return output, source, None
            record = extract_record(fetched[0], fetched[1])
        fetched_at = record.fetched_at
        output["exists"] = True
        output["in_snapshot"] = canonical in self.snapshot.records
        record = as_of(record, self.t)  # drops files uploaded after T (SPEC §13)
        spec = SpecifierSet("")
        try:
            reference = versions.reference_version(record, spec)
        except UnscorableError as exc:
            output["reason"] = exc.reason
            return output, source, fetched_at
        if reference not in record.version_meta:
            fetched = self.fetch_live(canonical, reference)
            if fetched is None:
                output["reason"] = "data unavailable"
                return output, "live", fetched_at
            record = add_version_meta(record, reference, fetched[0], fetched[1])
            source = "live"
        sig = compute_signals(record, spec, self.t)
        score = score_package(sig, self.baseline.distributions, self.baseline.sorted_totals)
        output.update(
            valid=True,
            effective_version=sig.effective_version,
            reference_version=sig.reference_version,
            final_score=score.final_score,
            total=score.placement.total,
            values=dict(sig.values),
            flags=[f.code for f in score.flags],
            beyond_baseline_range=list(score.placement.beyond_range),
        )
        return output, source, fetched_at

"""Phase orchestration and file IO: the only module that wires the subpackages together.

``deprisk.agent.loop`` (and so ``anthropic``) is imported lazily inside the
functions that need it, so ``--no-llm`` runs never load the SDK.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from deprisk import config
from deprisk.config import ConfigError, llm_settings
from deprisk.data.models import FetchError, PackageRecord, Requirement, Snapshot
from deprisk.data.pypi_client import FetchReport, PyPIClient, top_package_names
from deprisk.data.records import add_version_meta, extract_record
from deprisk.data.requirements import parse_requirements
from deprisk.data.snapshot import load_snapshot, reference_time, save_snapshot
from deprisk.reporting.report_md import render_report
from deprisk.reporting.results_json import write_results
from deprisk.risk.analysis import analyze
from deprisk.risk.models import UnscorableError
from deprisk.risk.versions import reference_version

if TYPE_CHECKING:
    import httpx

log = logging.getLogger(__name__)

DATA_UNAVAILABLE = "data unavailable"
DEFAULT_BASELINE_DEFINITION = (
    f"top {config.TOP_N} PyPI projects by downloads (hugovk top-pypi-packages)"
)


class SnapshotSource(Protocol):
    """What ``build_snapshot`` needs from a PyPI client (``PyPIClient`` or a test stub)."""

    def get_top_list(self) -> tuple[Any, datetime]: ...
    def get_project(self, name: str) -> tuple[Any, datetime] | None: ...
    def get_version(self, name: str, version: str) -> tuple[Any, datetime] | None: ...


def fetch_baseline(
    limit: int | None = None,
    *,
    refresh: bool = False,
    cache_dir: Path = config.CACHE_DIR,
    http: httpx.Client | None = None,
) -> FetchReport:
    """Phase A, step 1: cache the top list and the first ``limit`` (default TOP_N) projects.

    Resumable: cached responses are reused unless ``refresh`` is set.
    """
    n = config.TOP_N if limit is None else limit
    if not 1 <= n <= config.TOP_N:
        raise ConfigError(f"--limit must be between 1 and {config.TOP_N}, got {n}")
    with PyPIClient(cache_dir, client=http, refresh=refresh) as pypi:
        top_list, fetched_at = pypi.get_top_list()
        log.info(
            "Top list last_update %s (fetched %s); fetching %d projects",
            top_list.get("last_update"),
            fetched_at.isoformat(),
            n,
        )
        return pypi.fetch_projects(top_package_names(top_list, n))


def _needed_versions(record: PackageRecord, specs: Sequence[SpecifierSet]) -> list[str]:
    """Reference versions (one per specifier) whose metadata the record does not hold yet."""
    needed: set[str] = set()
    for spec in specs:
        try:
            version = reference_version(record, spec)
        except UnscorableError:
            continue  # unscored in Phase B with its reason; nothing to fetch
        if version not in record.version_meta:
            needed.add(version)
    return sorted(needed)


def _load_record(
    client: SnapshotSource, name: str, specs: Sequence[SpecifierSet]
) -> PackageRecord | None:
    """Project record plus every needed version endpoint; None = data unavailable."""
    try:
        fetched = client.get_project(name)
        if fetched is None:
            return None
        record = extract_record(*fetched)
        for version in _needed_versions(record, specs):
            version_fetched = client.get_version(name, version)
            if version_fetched is None:
                log.warning("%s: version endpoint %s not found", name, version)
                return None
            record = add_version_meta(record, version, *version_fetched)
    except FetchError as exc:
        log.warning("%s: %s", name, exc)
        return None
    return record


def build_snapshot(
    client: SnapshotSource,
    names: Sequence[str],
    requirements: Sequence[Requirement],
    include_targets: bool,
    *,
    definition: str = DEFAULT_BASELINE_DEFINITION,
) -> Snapshot:
    """Phase A: extract every baseline record and the version metadata scoring needs.

    Baseline packages need their reference version for an empty specifier; targets
    also need it for their own specifier. A package whose project or needed version
    endpoint cannot be fetched is excluded as "data unavailable" (never imputed).
    ``include_targets`` (smoke runs only) adds the requirement names to the baseline.
    """
    baseline = list(dict.fromkeys(canonicalize_name(n) for n in names))
    targets = {r.name: r.specifier for r in requirements}
    if include_targets:
        baseline += [n for n in targets if n not in baseline]
    top_list, top_fetched_at = client.get_top_list()

    records: dict[str, PackageRecord] = {}
    exclusions: dict[str, str] = {}
    for done, name in enumerate(baseline, 1):
        specs = [SpecifierSet("")] + ([targets[name]] if name in targets else [])
        record = _load_record(client, name, specs)
        if record is None:
            exclusions[name] = DATA_UNAVAILABLE
        else:
            records[name] = record
        if done % config.FETCH_PROGRESS_EVERY == 0 or done == len(baseline):
            log.info("Extracted %d/%d packages", done, len(baseline))

    t = reference_time(top_fetched_at, records.values())
    snapshot_id = hashlib.sha256(
        json.dumps([t.isoformat(), baseline, config.CONFIG_HASH]).encode()
    ).hexdigest()[:16]
    meta = {
        "id": snapshot_id,
        "T": t.isoformat(),
        "top_list": {
            "last_update": top_list.get("last_update"),
            "fetched_at": top_fetched_at.isoformat(),
        },
        "baseline": {
            "definition": definition,
            "n_requested": len(baseline),
            "include_targets": include_targets,
            "targets": sorted(targets),
        },
        "env": {
            "python_full_version": config.PYTHON_FULL_VERSION,
            "platform_arch": config.PLATFORM_ARCH,
            "manylinux_glibc_minors": list(config.MANYLINUX_GLIBC_MINORS),
            "legacy_manylinux": list(config.LEGACY_MANYLINUX),
            "marker_env": dict(config.MARKER_ENV),
        },
        "config_hash": config.CONFIG_HASH,
        "exclusions": dict(sorted(exclusions.items())),
    }
    log.info(
        "Snapshot %s: %d records, %d excluded, T=%s",
        snapshot_id,
        len(records),
        len(exclusions),
        meta["T"],
    )
    return Snapshot(meta=meta, baseline_names=tuple(baseline), records=records)


def _baseline_names(top_list: Any, limit: int | None, sample: int | None) -> tuple[list[str], str]:
    """Baseline names and their human-readable definition (recorded in the snapshot)."""
    names = top_package_names(top_list, config.TOP_N)
    source = "PyPI projects by downloads"
    if sample is not None:
        # Evenly spaced ranks keep a small sample representative of the whole top list.
        picked = [names[i * len(names) // sample] for i in range(sample)]
        return picked, f"{sample} evenly spaced ranks of the top {config.TOP_N} {source}"
    if limit is not None:
        return names[:limit], f"top {limit} {source} (hugovk top-pypi-packages)"
    return names, f"top {config.TOP_N} {source} (hugovk top-pypi-packages)"


def create_snapshot(
    out: Path,
    *,
    limit: int | None = None,
    sample: int | None = None,
    requirements_path: Path | None = config.REQUIREMENTS_PATH,
    include_targets: bool = False,
    cache_dir: Path = config.CACHE_DIR,
    http: httpx.Client | None = None,
) -> Snapshot:
    """Phase A, step 2: select the baseline, build the snapshot (fetching only what the
    cache lacks) and save it to ``out``. Arguments are checked before any request."""
    if limit is not None and sample is not None:
        raise ConfigError("Use either --limit or --sample, not both")
    size = limit if limit is not None else sample
    if size is not None and not 1 <= size <= config.TOP_N:
        raise ConfigError(f"--limit/--sample must be between 1 and {config.TOP_N}, got {size}")
    requirements: list[Requirement] = []
    if requirements_path is not None:
        requirements, issues = parse_requirements(requirements_path)
        for issue in issues:
            log.warning(
                "%s line %d not used (%s): %s",
                requirements_path,
                issue.line_no,
                issue.reason,
                issue.line,
            )
    with PyPIClient(cache_dir, client=http) as client:
        top_list, _ = client.get_top_list()
        names, definition = _baseline_names(top_list, limit, sample)
        if include_targets:
            definition += ", plus the requirement targets"
        snap = build_snapshot(client, names, requirements, include_targets, definition=definition)
    save_snapshot(snap, out)
    excluded_targets = sorted(r.name for r in requirements if r.name in snap.meta["exclusions"])
    if excluded_targets:
        log.warning("Targets excluded (data unavailable): %s", ", ".join(excluded_targets))
    return snap


def run_analysis(
    requirements_path: Path,
    snapshot_path: Path,
    out_dir: Path,
    *,
    use_llm: bool,
    top_n: int = config.AGENT_TOP_N,
) -> int:
    """Phase B (Phase C from M7): score, rank, write results.json and REPORT.md.

    Returns the exit code: 0 ok, 1 invalid run (an unscored target; outputs are still
    written). Raises ConfigError or SnapshotDataError for unusable inputs (exit 2).
    """
    if top_n < 1:
        raise ConfigError(f"--top-n must be at least 1, got {top_n}")
    if use_llm:
        raise ConfigError("The agent phase is not implemented yet (M7); run with --no-llm")
    requirements, issues = parse_requirements(requirements_path)
    snapshot = load_snapshot(snapshot_path)
    result = analyze(snapshot, requirements, issues=issues)
    write_results(result, None, out_dir / "results.json")
    (out_dir / "REPORT.md").write_text(render_report(result, None), encoding="utf-8")
    log.info(
        "Scored %d of %d packages; outputs in %s", len(result.ranked), len(requirements), out_dir
    )
    for name, reason in result.unscored.items():
        log.error("Not scored: %s (%s)", name, reason)
    return 1 if result.unscored else 0


def check_llm() -> dict[str, Any]:
    """Run the LLM connectivity check with the configured model and effort."""
    from deprisk.agent.loop import check_connectivity, make_client

    settings = llm_settings()
    return check_connectivity(make_client(settings), settings)

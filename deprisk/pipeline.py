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
from deprisk.data.snapshot import reference_time
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


def check_llm() -> dict[str, Any]:
    """Run the LLM connectivity check with the configured model and effort."""
    from deprisk.agent.loop import check_connectivity, make_client

    settings = llm_settings()
    return check_connectivity(make_client(settings), settings)

"""Phase B (SPEC §17): score and rank the targets against the frozen baseline.

Pure: reads only the snapshot, the parsed requirements, ``T`` and config. Targets that
are missing from the snapshot or have no reference version are reported in
``unscored`` with their reason (FR12), never dropped.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from deprisk import config
from deprisk.data.models import ParseIssue, Requirement, Snapshot
from deprisk.risk.baseline import DATA_UNAVAILABLE, build_baseline, summarise
from deprisk.risk.models import AnalysisResult, PackageScore, UnscorableError
from deprisk.risk.scoring import rank, score_package
from deprisk.risk.signals import compute_signals

NOT_IN_SNAPSHOT = "not in snapshot"


def analyze(
    snapshot: Snapshot,
    requirements: Sequence[Requirement],
    t: datetime | None = None,
    issues: Sequence[ParseIssue] = (),
) -> AnalysisResult:
    """Rank every target; ``t`` defaults to the snapshot's ``T`` (D13).

    A repeated requirement name is scored once (its first line). Missing metadata for a
    target's reference version raises SnapshotDataError: the snapshot was built for
    other requirements, and data is never fetched silently.
    """
    t = t or datetime.fromisoformat(snapshot.meta["T"])
    baseline = build_baseline(snapshot, t)
    excluded = snapshot.meta.get("exclusions", {})

    scores: list[PackageScore] = []
    unscored: dict[str, str] = {}
    seen: set[str] = set()
    for req in requirements:
        if req.name in seen:
            continue
        seen.add(req.name)
        record = snapshot.records.get(req.name)
        if record is None:
            reason = DATA_UNAVAILABLE if req.name in excluded else NOT_IN_SNAPSHOT
            unscored[req.name] = excluded.get(req.name, reason)
            continue
        try:
            sig = compute_signals(record, req.specifier, t)
        except UnscorableError as exc:
            unscored[req.name] = exc.reason
            continue
        scores.append(score_package(sig, baseline.distributions, baseline.sorted_totals))

    return AnalysisResult(
        ranked=tuple(rank(scores)),
        unscored=dict(sorted(unscored.items())),
        issues=tuple(issues),
        baseline_summary=summarise(baseline, snapshot),
        run_meta={
            "snapshot_id": snapshot.meta.get("id"),
            "T": t.isoformat(),
            "list_last_update": snapshot.meta.get("top_list", {}).get("last_update"),
            "baseline_n": baseline.n,
            "config_hash": config.CONFIG_HASH,
            "snapshot_config_hash": snapshot.meta.get("config_hash"),
        },
    )

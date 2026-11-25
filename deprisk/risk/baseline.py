"""The scored baseline: signals of every baseline package, reference distributions,
the total distribution, exclusions by reason, and the AC8 summary (SPEC §9)."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from packaging.specifiers import SpecifierSet

from deprisk import config
from deprisk.data.models import Snapshot
from deprisk.risk.models import Baseline, PackageSignals, UnscorableError
from deprisk.risk.scoring import build_distributions, place_signals, score_package
from deprisk.risk.signals import compute_signals

DATA_UNAVAILABLE = "data unavailable"


def build_baseline(snapshot: Snapshot, t: datetime) -> Baseline:
    """Score every baseline package at ``t`` with an empty specifier.

    Packages excluded at build time ("data unavailable") or without a reference version
    are counted by reason. Missing version metadata raises SnapshotDataError (hard error).
    """
    excluded_at_build = snapshot.meta.get("exclusions", {})
    exclusions: Counter[str] = Counter()
    signals: dict[str, PackageSignals] = {}
    for name in snapshot.baseline_names:
        record = snapshot.records.get(name)
        if name in excluded_at_build or record is None:
            exclusions[excluded_at_build.get(name, DATA_UNAVAILABLE)] += 1
            continue
        try:
            signals[name] = compute_signals(record, SpecifierSet(""), t)
        except UnscorableError as exc:
            exclusions[exc.reason] += 1

    dists = build_distributions(signals)
    sorted_totals = tuple(sorted(place_signals(sig, dists).total for sig in signals.values()))
    scores = {name: score_package(sig, dists, sorted_totals) for name, sig in signals.items()}
    return Baseline(
        signals=signals,
        scores=scores,
        distributions=dists,
        sorted_totals=sorted_totals,
        exclusions=dict(sorted(exclusions.items())),
        n=len(signals),
    )


def _p90(sorted_values: Sequence[float]) -> float:
    """90th percentile, nearest-rank method (always an observed value)."""
    return sorted_values[math.ceil(0.9 * len(sorted_values)) - 1]


def _round(x: float) -> float:
    return round(x, config.ROUND_DECIMALS)


def summarise(baseline: Baseline, snapshot: Snapshot) -> dict[str, Any]:
    """AC8 summary: n after exclusions, exclusions by reason, list date, ``T``, definition,
    and per-signal distribution summaries (n_s, median, p90, ties at the best value,
    unknown and partial counts)."""
    per_signal: dict[str, Any] = {}
    for s in config.SIGNALS:
        values = baseline.distributions[s].sorted_values
        higher = config.HIGHER_IS_RISKIER[s]
        best = values[0] if higher else values[-1]
        per_signal[s] = {
            "n_s": len(values),
            "median": _round(statistics.median(values)),
            "p90": _round(_p90(values)),
            "best_tie_share": _round(values.count(best) / len(values)),
            "unknown": sum(sig.values[s] is None for sig in baseline.signals.values()),
            "partial": sum(s in sig.partial for sig in baseline.signals.values()),
            "higher_is_riskier": higher,
        }
    totals = baseline.sorted_totals
    return {
        "n": baseline.n,
        "exclusions": dict(baseline.exclusions),
        "list_last_update": snapshot.meta.get("top_list", {}).get("last_update"),
        "T": snapshot.meta.get("T"),
        "definition": snapshot.meta.get("baseline", {}).get("definition"),
        "signals": per_signal,
        "totals": {"median": _round(statistics.median(totals)), "p90": _round(_p90(totals))},
    }

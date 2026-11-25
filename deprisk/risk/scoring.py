"""Rarity-based scoring against the baseline (SPEC §10).

For a value x of signal s, ``k`` = baseline values at least as risky as x (ties
included, direction from config) and ``q = max(k, 1) / n_s``. The contribution is
``-ln q``: 0 for the (most common) best value, ``ln n_s`` at most. Categories average
their signals, the total sums the categories, and the final score is the share of
baseline totals strictly below the package's total. A ranking index, not a probability.
"""

from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping

from deprisk import config
from deprisk.data.models import FrozenModel
from deprisk.risk.flags import critical_flags
from deprisk.risk.models import PackageScore, PackageSignals, Placement


def _round(x: float) -> float:
    return round(x, config.ROUND_DECIMALS) + 0.0  # + 0.0 turns -0.0 into 0.0


class Distribution(FrozenModel):
    """Known, complete baseline values of one signal, sorted ascending (its distribution)."""

    signal: str
    sorted_values: tuple[float, ...]

    def place(self, x: float) -> tuple[float, bool]:
        """``(q, beyond_range)``: the share of baseline values at least as risky as ``x``,
        floored at ``1/n_s``; ``beyond_range`` when ``x`` is riskier than every baseline value."""
        n = len(self.sorted_values)
        if config.HIGHER_IS_RISKIER[self.signal]:
            k = n - bisect_left(self.sorted_values, x)  # values >= x
        else:
            k = bisect_right(self.sorted_values, x)  # values <= x
        return max(k, 1) / n, k == 0


def build_distributions(baseline: Mapping[str, PackageSignals]) -> dict[str, Distribution]:
    """One distribution per scored signal; unknown and partial values are left out (§11).

    Raises ValueError if a signal has no usable baseline value.
    """
    dists: dict[str, Distribution] = {}
    for s in config.SIGNALS:
        values = sorted(
            v
            for sig in baseline.values()
            if (v := sig.values[s]) is not None and s not in sig.partial
        )
        if not values:
            raise ValueError(f"No baseline values for signal {s}: cannot build its distribution")
        dists[s] = Distribution(signal=s, sorted_values=tuple(float(v) for v in values))
    return dists


def place_signals(sig: PackageSignals, dists: Mapping[str, Distribution]) -> Placement:
    """Place every signal: unknown → neutral q; partial → q capped at neutral (never safer)."""
    q: dict[str, float] = {}
    contributions: dict[str, float] = {}
    beyond: list[str] = []
    for s in config.SIGNALS:
        value = sig.values[s]
        if value is None:
            qs = config.NEUTRAL_Q
        else:
            qs, is_beyond = dists[s].place(value)
            if is_beyond:
                beyond.append(s)
            if s in sig.partial:
                qs = min(qs, config.NEUTRAL_Q)
        q[s] = _round(qs)
        contributions[s] = _round(-math.log(qs))
    categories = {
        cat: _round(sum(contributions[s] for s in members) / len(members))
        for cat, members in config.CATEGORIES.items()
    }
    return Placement(
        q=q,
        contributions=contributions,
        categories=categories,
        total=_round(sum(categories.values())),
        beyond_range=tuple(beyond),
    )


def final_score(total: float, sorted_totals: tuple[float, ...]) -> float:
    """100 * share of baseline totals strictly below ``total`` (both rounded first)."""
    below = bisect_left(sorted_totals, _round(total))
    return round(100 * below / len(sorted_totals), config.SCORE_DECIMALS)


def score_package(
    sig: PackageSignals, dists: Mapping[str, Distribution], sorted_totals: tuple[float, ...]
) -> PackageScore:
    """Placement, final score and (display-only) flags of one package."""
    placement = place_signals(sig, dists)
    return PackageScore(
        name=sig.name,
        signals=sig,
        placement=placement,
        final_score=final_score(placement.total, sorted_totals),
        flags=critical_flags(sig, placement),
    )


def rank(scores: Iterable[PackageScore]) -> list[PackageScore]:
    """Final score desc, then total desc, then name asc (deterministic)."""
    return sorted(scores, key=lambda p: (-p.final_score, -p.placement.total, p.name))

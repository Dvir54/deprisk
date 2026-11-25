"""Placement on baseline distributions, contributions, totals, final score, ranking
(SPEC §10; AC4, AC4b)."""

from __future__ import annotations

import math
from typing import Any

import pytest

from deprisk.config import NEUTRAL_Q, ROUND_DECIMALS, SIGNALS
from deprisk.risk import scoring
from deprisk.risk.models import PackageScore, PackageSignals, Placement

LN2 = round(math.log(2), ROUND_DECIMALS)


def sig(name: str = "pkg", partial: tuple[str, ...] = (), **values: float | None) -> PackageSignals:
    """Signals with every scored value 0 unless overridden (S2=0 is its riskiest value)."""
    full: dict[str, float | None] = {s: 0.0 for s in SIGNALS}
    full.update(values)
    missing = [
        f for s, f in (("S6", "vulnerabilities"), ("S7", "requires_dist")) if full[s] is None
    ]
    return PackageSignals(
        name=name,
        effective_version="1.0",
        reference_version="1.0",
        values=full,
        partial=frozenset(partial),
        evidence={"missing": missing, "advisories": [], "malformed_requires_dist": []},
    )


def baseline(n: int, partial: dict[int, tuple[str, ...]] | None = None, **columns: list[Any]):
    """``n`` baseline packages; ``columns[s][i]`` is package i's value of signal s."""
    partial = partial or {}
    return {
        f"b{i}": sig(f"b{i}", partial.get(i, ()), **{s: col[i] for s, col in columns.items()})
        for i in range(n)
    }


def dists(n: int, **columns: list[Any]) -> dict[str, scoring.Distribution]:
    return scoring.build_distributions(baseline(n, **columns))


# --- per-signal placement (§10.1) ------------------------------------------------------


def test_direction_higher_is_riskier() -> None:
    d = dists(4, S1=[1, 2, 3, 4])["S1"]
    assert d.place(3) == (0.5, False)  # 3 and 4 are at least as risky
    assert d.place(1) == (1.0, False)


def test_direction_lower_is_riskier_for_s2() -> None:
    d = dists(4, S2=[1, 2, 3, 4])["S2"]
    assert d.place(2) == (0.5, False)  # 1 and 2 are at least as risky
    assert d.place(4) == (1.0, False)


def test_ties_counted_as_at_least_as_risky() -> None:
    d = dists(4, S6=[0, 0, 0, 5])["S6"]
    assert d.place(0) == (1.0, False)
    assert d.place(5) == (0.25, False)


def test_best_value_contributes_zero() -> None:
    d = dists(4, S1=[1, 2, 3, 4], S2=[1, 2, 3, 4])
    placement = scoring.place_signals(sig(S1=1, S2=4), d)
    assert all(c == 0.0 for c in placement.contributions.values())
    assert placement.total == 0.0


def test_worst_baseline_value_contributes_ln_n() -> None:
    d = dists(10, S1=list(range(1, 11)))
    placement = scoring.place_signals(sig(S1=10), d)
    assert placement.q["S1"] == pytest.approx(0.1)
    assert placement.contributions["S1"] == round(math.log(10), ROUND_DECIMALS)
    assert placement.beyond_range == ()


def test_value_beyond_baseline_floors_q_and_flags() -> None:
    d = dists(10, S1=list(range(1, 11)))
    assert d["S1"].place(11) == (0.1, True)
    placement = scoring.place_signals(sig(S1=11), d)
    assert placement.contributions["S1"] == round(math.log(10), ROUND_DECIMALS)
    assert placement.beyond_range == ("S1",)


def test_all_values_tied_gives_zero_for_everyone() -> None:
    d = dists(5, S1=[7] * 5)
    assert scoring.place_signals(sig(S1=7), d).contributions["S1"] == 0.0


# --- missing and partial values (§11, AC4b) ------------------------------------------------


def test_unknown_gets_ln2_and_is_excluded_from_n_s() -> None:
    d = dists(4, S6=[0, 1, None, None])
    assert d["S6"].sorted_values == (0.0, 1.0)  # n_s = 2: unknowns are not in the distribution
    placement = scoring.place_signals(sig(S6=None), d)
    assert placement.q["S6"] == NEUTRAL_Q
    assert placement.contributions["S6"] == LN2


def test_missing_never_scores_as_safe_value() -> None:
    """On a zero-inflated baseline the safe value scores 0, an unknown value never does."""
    d = dists(10, S6=[0] * 9 + [1])
    assert scoring.place_signals(sig(S6=0), d).contributions["S6"] == 0.0
    assert scoring.place_signals(sig(S6=None), d).contributions["S6"] == LN2 > 0


def test_partial_value_never_below_neutral() -> None:
    """A malformed-entry package whose valid count alone would score 0 gets at least ln 2."""
    base = baseline(11, partial={10: ("S7",)}, S7=[0] * 5 + [3] * 5 + [0])
    d = scoring.build_distributions(base)
    assert len(d["S7"].sorted_values) == 10  # the partial baseline value is excluded
    placement = scoring.place_signals(sig(S7=0, partial=("S7",)), d)
    assert placement.q["S7"] == NEUTRAL_Q
    assert placement.contributions["S7"] == LN2
    riskier = scoring.place_signals(sig(S7=3, partial=("S7",)), d)
    assert riskier.q["S7"] == 0.5  # already below neutral: kept


def test_empty_distribution_raises() -> None:
    with pytest.raises(ValueError, match="S6"):
        dists(3, S6=[None, None, None])


# --- aggregation (§10.3) -------------------------------------------------------------------


def test_category_is_mean_total_is_sum() -> None:
    d = dists(4, S1=[1, 2, 3, 4], S4=[0, 0, 1, 2], S7=[0, 1, 2, 3])
    p = scoring.place_signals(sig(S1=4, S4=2, S7=2), d)
    c = p.contributions
    assert c["S1"] == round(math.log(4), ROUND_DECIMALS)
    assert c["S2"] == 0.0  # every baseline S2 is 0: tied
    assert p.categories["maintenance"] == round((c["S1"] + c["S2"]) / 2, ROUND_DECIMALS)
    assert p.categories["compatibility"] == round((c["S4"] + c["S5"]) / 2, ROUND_DECIMALS)
    assert p.categories["security"] == c["S6"]
    assert p.categories["dependencies"] == c["S7"] == round(math.log(2), ROUND_DECIMALS)
    assert p.total == round(sum(p.categories.values()), ROUND_DECIMALS)


def test_final_score_strictly_less_share() -> None:
    totals = (0.0, 1.0, 1.0, 2.0)
    assert scoring.final_score(0.0, totals) == 0.0  # lowest total
    assert scoring.final_score(1.0, totals) == 25.0  # ties are not counted
    assert scoring.final_score(2.0, totals) == 75.0
    assert scoring.final_score(9.0, totals) == 100.0


def test_rounding_applied_before_comparison() -> None:
    assert scoring.final_score(0.1 + 0.2, (0.3,)) == 0.0  # 0.30000000000000004 ties 0.3


def score(name: str, final: float, total: float) -> PackageScore:
    placement = Placement(q={}, contributions={}, categories={}, total=total, beyond_range=())
    return PackageScore(
        name=name, signals=sig(name), placement=placement, final_score=final, flags=()
    )


def test_rank_tie_breaks_total_then_name() -> None:
    ranked = scoring.rank(
        [score("b", 50, 1.0), score("a", 50, 1.0), score("c", 50, 2.0), score("d", 90, 0.5)]
    )
    assert [s.name for s in ranked] == ["d", "c", "a", "b"]


def test_score_package_combines_placement_final_and_flags() -> None:
    base = baseline(4, S1=[1, 2, 3, 4])
    d = scoring.build_distributions(base)
    totals = tuple(sorted(scoring.place_signals(s, d).total for s in base.values()))
    result = scoring.score_package(sig("t", S1=4, S6=None), d, totals)
    assert result.final_score == 100.0
    assert [f.code for f in result.flags] == ["missing:vulnerabilities"]

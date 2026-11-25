"""Baseline signals, exclusions and the AC8 summary (SPEC §9)."""

from __future__ import annotations

import pytest

from deprisk.config import SIGNALS
from deprisk.data.models import SnapshotDataError
from deprisk.risk.baseline import build_baseline, summarise

CLEAN = {"classifiers": [], "requires_dist": [], "vulnerabilities": []}


def records(make_record) -> dict:
    """Four scorable packages (S7 = 0..3) plus one with unknown vulnerabilities."""
    out = {
        f"ok{i}": make_record(
            {"1.0": [{}]},
            {"1.0": {**CLEAN, "requires_dist": [f"d{j}" for j in range(i)]}},
            name=f"ok{i}",
        )
        for i in range(4)
    }
    out["unknown"] = make_record(
        {"1.0": [{}]}, {"1.0": {**CLEAN, "vulnerabilities": None}}, name="unknown"
    )
    return out


def test_exclusions_counted_by_reason(make_record, make_snapshot, fixed_t) -> None:
    recs = records(make_record)
    recs["pre"] = make_record({"1.0a1": [{}]}, name="pre")
    recs["yanked"] = make_record({"1.0": [{"yanked": True}]}, name="yanked")
    recs["pre2"] = make_record({"2.0b1": [{}]}, name="pre2")
    snap = make_snapshot(recs, exclusions={"gone": "data unavailable"})
    base = build_baseline(snap, fixed_t)
    assert base.exclusions == {
        "data unavailable": 1,
        "only pre-releases": 2,
        "only yanked files": 1,
    }
    assert base.n == 5
    assert set(base.signals) == set(base.scores) == {"ok0", "ok1", "ok2", "ok3", "unknown"}


def test_baseline_totals_sorted_and_scored(make_record, make_snapshot, fixed_t) -> None:
    base = build_baseline(make_snapshot(records(make_record)), fixed_t)
    assert base.sorted_totals == tuple(sorted(s.placement.total for s in base.scores.values()))
    assert len(base.sorted_totals) == base.n
    assert base.distributions["S6"].sorted_values == (0.0,) * 4  # the unknown is excluded
    assert base.scores["ok0"].final_score == 0.0


def test_baseline_name_missing_from_records_is_data_unavailable(
    make_record, make_snapshot, fixed_t
) -> None:
    snap = make_snapshot(
        records(make_record), baseline_names=("ok0", "ok1", "ok2", "ok3", "unknown", "ghost")
    )
    assert build_baseline(snap, fixed_t).exclusions == {"data unavailable": 1}


def test_missing_baseline_version_meta_is_hard_error(make_record, make_snapshot, fixed_t) -> None:
    recs = records(make_record)
    recs["nometa"] = make_record({"1.0": [{}]}, name="nometa")
    with pytest.raises(SnapshotDataError):
        build_baseline(make_snapshot(recs), fixed_t)


def test_summary_has_ac8_fields(make_record, make_snapshot, fixed_t) -> None:
    snap = make_snapshot(records(make_record), exclusions={"gone": "data unavailable"})
    summary = summarise(build_baseline(snap, fixed_t), snap)
    assert summary["n"] == 5
    assert summary["exclusions"] == {"data unavailable": 1}
    assert summary["list_last_update"] == "2026-11-01 06:41:05"
    assert summary["T"] == fixed_t.isoformat()
    assert summary["definition"] == "test baseline"
    assert set(summary["signals"]) == set(SIGNALS)
    s7 = summary["signals"]["S7"]
    assert s7 == {  # S7 values 0, 1, 2, 3 and 0 ("unknown" lacks only vulnerabilities)
        "n_s": 5,
        "median": 1.0,
        "p90": 3.0,
        "best_tie_share": 0.4,
        "unknown": 0,
        "partial": 0,
        "higher_is_riskier": True,
    }
    assert summary["signals"]["S6"]["unknown"] == 1
    assert summary["signals"]["S6"]["best_tie_share"] == 1.0
    assert set(summary["totals"]) == {"median", "p90"}

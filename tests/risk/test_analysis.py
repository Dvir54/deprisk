"""Phase B: score and rank the targets against the baseline (pure, no IO; FR7-FR9, FR12)."""

from __future__ import annotations

import random
from datetime import timedelta

from packaging.specifiers import SpecifierSet

from deprisk.config import CONFIG_HASH
from deprisk.data.models import ParseIssue, Requirement
from deprisk.risk.analysis import analyze

CLEAN = {"classifiers": [], "requires_dist": [], "vulnerabilities": []}


def req(name: str, spec: str = "") -> Requirement:
    return Requirement(name=name, specifier=SpecifierSet(spec), line=f"{name}{spec}")


def snapshot(make_record, make_snapshot, fixed_t, **extra):
    """Baseline of 6 packages with spread-out ages and dependency counts."""
    recs = {}
    for i in range(6):
        upload = (fixed_t - timedelta(days=100 * (i + 1))).isoformat()
        deps = [f"d{j}" for j in range(i)]
        recs[f"p{i}"] = make_record(
            {"1.0": [{"upload_time": upload}]},
            {"1.0": {**CLEAN, "requires_dist": deps}},
            name=f"p{i}",
        )
    recs["two"] = make_record(
        {"1.0": [{}], "2.0": [{}]},
        {"2.0": CLEAN, "1.0": {**CLEAN, "vulnerabilities": [{"id": "OLD-1", "fixed_in": ["2.0"]}]}},
        name="two",
    )
    recs["pre"] = make_record({"1.0rc1": [{}]}, name="pre")
    recs.update(extra)
    return make_snapshot(recs, exclusions={"gone": "data unavailable"})


def test_targets_scored_and_ranked(make_record, make_snapshot, fixed_t) -> None:
    result = analyze(
        snapshot(make_record, make_snapshot, fixed_t), [req("p0"), req("p5"), req("p2")]
    )
    assert [s.name for s in result.ranked] == ["p5", "p2", "p0"]  # oldest, most dependencies first
    assert result.ranked[-1].final_score == 0.0
    assert result.unscored == {}


def test_missing_target_reported_unscored(make_record, make_snapshot, fixed_t) -> None:
    snap = snapshot(make_record, make_snapshot, fixed_t)
    result = analyze(snap, [req("p1"), req("absent"), req("gone"), req("pre")])
    assert [s.name for s in result.ranked] == ["p1"]
    assert result.unscored == {
        "absent": "not in snapshot",
        "gone": "data unavailable",
        "pre": "only pre-releases",
    }


def test_target_specifier_selects_reference_version(make_record, make_snapshot, fixed_t) -> None:
    result = analyze(snapshot(make_record, make_snapshot, fixed_t), [req("two", "<2")])
    (score,) = result.ranked
    assert score.signals.reference_version == "1.0"
    assert score.signals.values["S6"] == 1
    # Every baseline package has 0 advisories, so 1 lies beyond the baseline range (§10.1).
    assert [f.code for f in score.flags] == [
        "advisory_with_fix",
        "beyond_baseline_range",
        "sdist_only",
    ]
    assert score.placement.beyond_range == ("S6",)


def test_analysis_deterministic_and_order_independent(make_record, make_snapshot, fixed_t) -> None:
    snap = snapshot(make_record, make_snapshot, fixed_t)
    reqs = [req("p0"), req("p3"), req("two"), req("absent")]
    first = analyze(snap, reqs)
    items = list(snap.records.items())
    random.Random(7).shuffle(items)
    shuffled = snap.model_copy(
        update={"records": dict(items), "baseline_names": tuple(reversed(snap.baseline_names))}
    )
    assert analyze(shuffled, list(reversed(reqs))) == first
    assert analyze(snap, reqs) == first


def test_t_defaults_to_snapshot_t_and_run_meta(make_record, make_snapshot, fixed_t) -> None:
    snap = snapshot(make_record, make_snapshot, fixed_t)
    issue = ParseIssue(line_no=3, line="-r other.txt", reason="unsupported: -r")
    result = analyze(snap, [req("p1")], issues=[issue])
    assert result.issues == (issue,)
    assert result.run_meta == {
        "snapshot_id": "test-snapshot",
        "T": fixed_t.isoformat(),
        "list_last_update": "2026-11-01 06:41:05",
        "baseline_n": 7,
        "config_hash": CONFIG_HASH,  # the config that scored this run
        "snapshot_config_hash": "test",  # the config the snapshot was built with
    }
    assert result.baseline_summary["n"] == 7
    later = analyze(snap, [req("p1")], t=fixed_t + timedelta(days=365))
    assert later.ranked[0].signals.values["S1"] > result.ranked[0].signals.values["S1"]


def test_duplicate_requirement_scored_once(make_record, make_snapshot, fixed_t) -> None:
    result = analyze(snapshot(make_record, make_snapshot, fixed_t), [req("p1"), req("p1", ">=1")])
    assert [s.name for s in result.ranked] == ["p1"]

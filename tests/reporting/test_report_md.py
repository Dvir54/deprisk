"""REPORT.md: a short report with three sections (summary, ranking, recommendations)."""

from __future__ import annotations

from packaging.specifiers import SpecifierSet

from deprisk.agent.models import Recommendation, ToolCall
from deprisk.data.models import ParseIssue, Requirement
from deprisk.reporting.report_md import render_report
from deprisk.risk.analysis import analyze

REQS = [
    Requirement(name=n, specifier=SpecifierSet(s), line=f"{n}{s}")
    for n, s in [("fresh0", ""), ("legacy", ">=2"), ("fallback", ""), ("beta", ""), ("absent", "")]
]


def result(mini_snapshot):
    issue = ParseIssue(line_no=9, line="-r more.txt", reason="unsupported option: not followed")
    return analyze(mini_snapshot, REQS, issues=[issue])


def _recommendations() -> list[Recommendation]:
    call = ToolCall(
        id="call_1",
        package="legacy",
        name="lookup_candidate",
        args={"name": "enum"},
        output={},
        source="snapshot",
        origin="agent",
        fetched_at=None,
    )
    validated = Recommendation(
        package="legacy",
        status="validated",
        attempts=2,
        llm_requests=3,
        errors=("attempt 1: version 9 does not exist",),
        calls=(call,),
        model="claude-sonnet-5-5",
        usage={"input_tokens": 10},
        output={
            "action": "replace",
            "target": "enum",
            "replacement_type": "stdlib",
            "finding": "sdist_only",
            "rationale": "Only an sdist exists.",
            "evidence": [{"call_id": "call_1", "field": "flags[1].code", "value": "sdist_only"}],
            "suitability_assumptions": ["Same API.", "Small migration."],
            "uncertainties": ["Usage unknown."],
            "confidence": "medium",
        },
    )
    unresolved = Recommendation(
        package="fresh0",
        status="unresolved",
        attempts=3,
        llm_requests=3,
        errors=("attempt 3: stop_reason end_turn",),
        calls=(),
        model="claude-sonnet-5-5",
        usage={},
        output=None,
    )
    return [validated, unresolved]


def test_only_three_sections(mini_snapshot) -> None:
    text = render_report(result(mini_snapshot), _recommendations())
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == ["## Summary", "## Dependency ranking", "## Top 2 recommendations"]


def test_summary_states_environment_baseline_and_score_meaning(mini_snapshot) -> None:
    text = render_report(result(mini_snapshot), None)
    summary = text.split("## Dependency ranking")[0]
    assert "CPython 3.12 on Linux x86_64" in summary
    assert "test baseline; list dated 2026-11-01; 7 scorable packages" in summary
    assert "data unavailable: 1" in summary
    assert "5 packages analyzed, 3 scored" in summary
    assert "absent (not in snapshot)" in summary and "beta (only pre-releases)" in summary
    assert "line 9 `-r more.txt`" in summary
    assert "not a probability" in summary and "`docs/RISK_MODEL.md`" in summary
    assert "T = 2026-11-25 00:00 UTC" in summary
    assert "S1 days since the last upload" in summary  # legend for the agent's signal ids


def test_ranking_table_in_rank_order_with_main_factors(mini_snapshot) -> None:
    text = render_report(result(mini_snapshot), None)
    assert "| Rank | Package | Effective version | Risk score | Main risk factors |" in text
    rows = {
        line.split("|")[2].strip(): line
        for line in text.splitlines()
        if line[:4] in ("| 1 ", "| 2 ", "| 3 ")
    }
    assert list(rows) == ["legacy", "fallback", "fresh0"]
    assert "1 known vulnerability (no fix listed)" in rows["legacy"]
    assert "last upload 12.4 years ago" in rows["legacy"]
    assert "pip falls back to the old release 1.0" in rows["fallback"]
    assert " 1 releases" not in text


def test_detail_stays_out_of_the_report(mini_snapshot) -> None:
    text = render_report(result(mini_snapshot), _recommendations())
    for detail in ("call_1", "flags[1]", "contribution", "-ln", "p90", "PYSEC-1", "attempt 1:"):
        assert detail not in text, detail
    assert "results.json" in text  # where the detail lives


def test_recommendations_action_rationale_and_assumptions(mini_snapshot) -> None:
    text = render_report(result(mini_snapshot), _recommendations())
    assert "### 1. legacy: replace with `enum` (standard-library module)" in text
    assert "Only an sdist exists." in text
    assert "Assumptions: Same API; Small migration." in text
    assert "Usage unknown." not in text  # uncertainties stay in results.json
    assert "### 3. fresh0: no validated recommendation" in text
    assert "suitability not verified" in text


def test_no_llm_says_recommendations_not_run(mini_snapshot) -> None:
    text = render_report(result(mini_snapshot), None)
    assert "## Top recommendations" in text and "Not run (`--no-llm`)" in text


def test_report_deterministic(mini_snapshot) -> None:
    recs = _recommendations()
    assert render_report(result(mini_snapshot), recs) == render_report(result(mini_snapshot), recs)

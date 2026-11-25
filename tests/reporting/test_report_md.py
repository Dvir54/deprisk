"""REPORT.md: ranked table, explanations, flags, unscored packages, baseline summary."""

from __future__ import annotations

from packaging.specifiers import SpecifierSet

from deprisk.data.models import ParseIssue, Requirement
from deprisk.reporting.report_md import render_report
from deprisk.risk.analysis import analyze

REQS = [
    Requirement(name=n, specifier=SpecifierSet(s), line=f"{n}{s}")
    for n, s in [("fresh0", ""), ("legacy", ">=2"), ("fallback", ""), ("beta", ""), ("absent", "")]
]


def report(mini_snapshot) -> str:
    issue = ParseIssue(line_no=9, line="-r more.txt", reason="unsupported option: not followed")
    return render_report(analyze(mini_snapshot, REQS, issues=[issue]), None)


def test_ranked_table_in_rank_order(mini_snapshot) -> None:
    text = report(mini_snapshot)
    assert "| Rank | Package |" in text
    rows = [
        line
        for line in text.splitlines()
        if line.startswith("| 1 ") or line.startswith("| 2 ") or line.startswith("| 3 ")
    ]
    assert [r.split("|")[2].strip() for r in rows] == ["legacy", "fallback", "fresh0"]


def test_explanations_flags_and_shares(mini_snapshot) -> None:
    text = report(mini_snapshot)
    assert "### 1. legacy" in text
    assert "of the baseline is as risky or riskier" in text
    assert "unknown (metadata missing)" in text  # legacy's requires_dist is null
    assert "unfixed_advisory" in text and "PYSEC-1" in text
    assert "python_fallback" in text  # fallback


def test_unscored_issues_and_baseline_summary(mini_snapshot) -> None:
    text = report(mini_snapshot)
    assert "## Not scored" in text
    assert "| absent | not in snapshot |" in text
    assert "| beta | only pre-releases |" in text
    assert "-r more.txt" in text
    assert "## Baseline summary" in text
    assert "test baseline" in text  # the baseline definition
    assert "data unavailable: 1" in text
    assert "not a probability" in text


def test_no_llm_says_recommendations_not_run(mini_snapshot) -> None:
    assert "Not run (`--no-llm`)" in report(mini_snapshot)


def test_report_deterministic(mini_snapshot) -> None:
    assert report(mini_snapshot) == report(mini_snapshot)

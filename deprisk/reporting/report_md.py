"""REPORT.md: the human-readable report (SPEC §16).

A ranked table, then per package every signal that adds to its score (raw value and the
share of the baseline that is as risky or riskier), its flags and evidence-only
signals, then unscored packages, the baseline summary and the recommendations.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from deprisk import config
from deprisk.agent.models import Recommendation
from deprisk.risk.models import AnalysisResult, PackageScore

SIGNAL_LABELS = {
    "S1": "days since the last upload",
    "S2": "final releases in the last 24 months",
    "S4": "Python 3.12 evidence",
    "S5": "install path",
    "S6": "distinct vulnerabilities on the reference version",
    "S7": "direct runtime dependencies",
}
S4_STATES = {
    0: "positive 3.12 evidence (classifier or cp312 wheel)",
    1: "requires_python declared, no 3.12 evidence",
    2: "no requires_python and no Python 3 minor classifiers",
    3: "only stale Python 3 classifiers (< 3.12)",
    4: "pip falls back to an older release",
    5: "no eligible version",
}
S5_STATES = {0: "wheel", 1: "sdist only (build required)", 2: "no eligible version"}
EVIDENCE_LABELS = {
    "S3": "effective version age (days)",
    "S8": "PyPI role accounts",
    "S9": "share of fully yanked releases",
    "S10": "0.x reference version",
    "S14": "'Development Status :: 7 - Inactive'",
}


def _value(signal: str, value: float | None) -> str:
    if value is None:
        return "unknown (metadata missing)"
    if signal == "S4":
        return f"state {value:.0f}: {S4_STATES[int(value)]}"
    if signal == "S5":
        return f"state {value:.0f}: {S5_STATES[int(value)]}"
    if signal == "S1":
        return f"{value:.0f} days"
    return f"{value:.0f}"


def _pct(q: float) -> str:
    return f"{100 * q:.2f}%"


def _flag_text(evidence: dict[str, Any]) -> str:
    return json.dumps(evidence, sort_keys=True)


def _ranking(result: AnalysisResult) -> list[str]:
    lines = [
        "| Rank | Package | Requirement | Effective version | Score | Total | Flags |",
        "|---:|---|---|---|---:|---:|---|",
    ]
    for i, p in enumerate(result.ranked, 1):
        spec = p.signals.evidence.get("specifier") or "(any)"
        flags = ", ".join(f.code for f in p.flags) or "-"
        lines.append(
            f"| {i} | {p.name} | {spec} | {p.signals.effective_version or 'none'} | "
            f"{p.final_score:.2f} | {p.placement.total:.3f} | {flags} |"
        )
    return lines


def _details(i: int, p: PackageScore) -> list[str]:
    sig, placement = p.signals, p.placement
    lines = [
        f"### {i}. {p.name}",
        "",
        f"Score **{p.final_score:.2f}** (riskier than {p.final_score:.2f}% of the baseline), "
        f"total {placement.total:.3f}. Effective version {sig.effective_version or 'none'}, "
        f"reference version {sig.reference_version}. Categories: "
        + ", ".join(f"{c} {v:.3f}" for c, v in placement.categories.items())
        + ".",
        "",
    ]
    # Every contributing signal, largest first, so the total is fully explained.
    drivers = sorted(
        (s for s in config.SIGNALS if placement.contributions[s] > 0),
        key=lambda s: (-placement.contributions[s], s),
    )
    if drivers:
        lines.append("Signals driving the score:")
        for s in drivers:
            value = sig.values[s]
            share = (
                "neutral placement (no data)"
                if value is None
                else f"only {_pct(placement.q[s])} of the baseline is as risky or riskier"
            )
            partial = " (lower bound: malformed entries)" if s in sig.partial else ""
            lines.append(
                f"- {s} {SIGNAL_LABELS[s]}: {_value(s, value)}{partial}; {share} "
                f"(contribution {placement.contributions[s]:.3f})"
            )
    else:
        lines.append("No signal is rarer than the most common value in the baseline.")
    if p.flags:
        lines += ["", "Flags:"]
        lines += [f"- `{f.code}`: {_flag_text(dict(f.evidence))}" for f in p.flags]
    evidence = ", ".join(
        f"{EVIDENCE_LABELS[k]}: {_fmt(sig.evidence.get(k))}" for k in EVIDENCE_LABELS
    )
    lines += ["", f"Evidence only (not scored): {evidence}.", ""]
    return lines


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    return "n/a" if value is None else str(value)


def _not_scored(result: AnalysisResult) -> list[str]:
    lines: list[str] = []
    if result.unscored:
        lines += ["## Not scored", "", "| Package | Reason |", "|---|---|"]
        lines += [f"| {name} | {reason} |" for name, reason in result.unscored.items()]
        lines.append("")
    if result.issues:
        lines += ["## Requirement lines not used", "", "| Line | Text | Reason |", "|---:|---|---|"]
        lines += [f"| {i.line_no} | `{i.line}` | {i.reason} |" for i in result.issues]
        lines.append("")
    return lines


def _baseline(result: AnalysisResult) -> list[str]:
    summary = result.baseline_summary
    exclusions = ", ".join(f"{k}: {v}" for k, v in summary["exclusions"].items()) or "none"
    lines = [
        "## Baseline summary",
        "",
        f"- Definition: {summary['definition']}",
        f"- Packages scored (n): {summary['n']}; excluded: {exclusions}",
        f"- Top list last updated: {summary['list_last_update']}; reference time T: {summary['T']}",
        f"- Totals: median {summary['totals']['median']:.3f}, p90 {summary['totals']['p90']:.3f}",
        "",
        "| Signal | Meaning | Riskier when | n_s | Median | p90 | Ties at best "
        "| Unknown | Partial |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for s, d in summary["signals"].items():
        direction = "higher" if d["higher_is_riskier"] else "lower"
        lines.append(
            f"| {s} | {SIGNAL_LABELS[s]} | {direction} | {d['n_s']} | {d['median']:g} | "
            f"{d['p90']:g} | {_pct(d['best_tie_share'])} | {d['unknown']} | {d['partial']} |"
        )
    return [*lines, ""]


def _recommendations(recommendations: Sequence[Recommendation] | None) -> list[str]:
    lines = ["## Recommendations for the top packages", ""]
    if recommendations is None:
        return [*lines, "Not run (`--no-llm`).", ""]
    lines += ["Labels: facts validated; suitability not verified.", ""]
    for rec in recommendations:
        lines.append(f"### {rec.package}: {rec.status}")
        if rec.output:
            lines += [f"- {k}: {_fmt(v)}" for k, v in sorted(rec.output.items())]
        if rec.errors:
            lines.append(f"- validation errors: {'; '.join(rec.errors)}")
        lines.append("")
    return lines


def render_report(result: AnalysisResult, recommendations: Sequence[Recommendation] | None) -> str:
    """The full Markdown report (deterministic for the same inputs)."""
    meta = result.run_meta
    lines = [
        "# Dependency risk report",
        "",
        f"Snapshot `{meta['snapshot_id']}`, T = {meta['T']}, baseline n = {meta['baseline_n']}, "
        f"config `{meta['config_hash']}`.",
        "",
        "The score says how much riskier a package looks than the baseline: a score of X "
        "means its total is higher than X% of the baseline totals. It is a relative index, "
        "not a probability of failure, and unusual is not the same as unsafe. Each signal "
        "adds -ln(q), where q is the share of the baseline that is as risky or riskier.",
        "",
        "## Ranking",
        "",
        *_ranking(result),
        "",
        "## Package details",
        "",
    ]
    for i, p in enumerate(result.ranked, 1):
        lines += _details(i, p)
    lines += _not_scored(result)
    lines += _recommendations(recommendations)
    lines += _baseline(result)
    return "\n".join(lines).rstrip() + "\n"

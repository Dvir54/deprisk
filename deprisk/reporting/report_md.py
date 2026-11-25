"""REPORT.md: the short human-readable report (SPEC §16).

Three sections: a summary, the ranking of every package with its main risk factors in
plain words, and the top recommendations. Every detail (signal values, placements,
flags with evidence, the baseline distributions and the agent's tool-call log) lives in
results.json; the method lives in RISK_MODEL.md.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import UTC, datetime

from deprisk import config
from deprisk.agent.models import Recommendation
from deprisk.risk.models import AnalysisResult, PackageScore

_DAYS_PER_YEAR = 365.25
# A factor is "main" when the package is riskier than at least half of the baseline on it,
# i.e. its contribution is at least that of the neutral placement (ln 2).
_MAIN_FACTOR_MIN = -math.log(config.NEUTRAL_Q)
_S4_TEXT = {
    0: "Python 3.12 support shown",
    1: "Python 3.12 support not confirmed (only requires_python)",
    2: "no Python version metadata",
    3: "classifiers only for Python 3 versions before 3.12",
    5: "no release installable on 3.12",
}
_S5_TEXT = {1: "sdist only (built from source at install)", 2: "no installable release"}
_REPLACEMENT_KIND = {"stdlib": "standard-library module", "pypi": "PyPI package"}
_SIGNAL_IDS = {
    "S1": "days since the last upload",
    "S2": "final releases in the last 24 months",
    "S4": "Python 3.12 evidence state",
    "S5": "install path state",
    "S6": "known vulnerabilities",
    "S7": "direct dependencies",
}


def _factor(signal: str, p: PackageScore) -> str:
    """One signal of one package in plain words, with its value."""
    value = p.signals.values[signal]
    if signal == "S1":
        years = value / _DAYS_PER_YEAR
        return (
            f"last upload {years:.1f} years ago"
            if years >= 1
            else f"last upload {value:.0f} days ago"
        )
    if signal == "S2":
        if value == 0:
            return "no release in 2 years"
        return "1 release in 2 years" if value == 1 else f"{value:.0f} releases in 2 years"
    if signal == "S4":
        if value == 4:
            return f"pip falls back to the old release {p.signals.effective_version}"
        return _S4_TEXT[int(value)]
    if signal == "S5":
        return _S5_TEXT[int(value)]
    if signal == "S6":
        if value is None:
            return "no vulnerability data"
        unfixed = next((f for f in p.flags if f.code == "unfixed_advisory"), None)
        n_unfixed = len(unfixed.evidence["vulnerabilities"]) if unfixed else 0
        noun = "vulnerability" if value == 1 else "vulnerabilities"
        if n_unfixed == value:
            return f"{value:.0f} known {noun} (no fix listed)"
        return f"{value:.0f} known {noun} ({n_unfixed} without a fix)"
    # S7
    if value is None:
        return "dependencies not declared on PyPI"
    prefix = "at least " if signal in p.signals.partial else ""
    return f"{prefix}{value:.0f} direct dependencies"


def _main_factors(p: PackageScore) -> str:
    contributions = p.placement.contributions
    main = sorted(
        (s for s in config.SIGNALS if contributions[s] >= _MAIN_FACTOR_MIN),
        key=lambda s: (-contributions[s], s),
    )[: config.REPORT_MAX_FACTORS]
    if not main:
        return "no signal riskier than the baseline middle"
    return "; ".join(_factor(s, p) for s in main)


def _summary(result: AnalysisResult) -> list[str]:
    summary, meta = result.baseline_summary, result.run_meta
    exclusions = ", ".join(f"{k}: {v}" for k, v in summary["exclusions"].items()) or "none"
    analyzed = len(result.ranked) + len(result.unscored)
    t = datetime.fromisoformat(meta["T"]).astimezone(UTC)
    lines = [
        "## Summary",
        "",
        f"- **Target environment:** CPython {config.PYTHON_VERSION[0]}.{config.PYTHON_VERSION[1]} "
        f"on Linux {config.PLATFORM_ARCH} (glibc 2.{config.MANYLINUX_GLIBC_MINORS[0]}, "
        "manylinux wheels), fresh install.",
        f"- **Baseline:** {summary['definition']}; list dated "
        f"{str(summary['list_last_update'])[:10]}; {summary['n']:,} scorable packages "
        f"(excluded: {exclusions}).",
        f"- **Analyzed:** {analyzed} packages analyzed, {len(result.ranked)} scored. "
        f"Snapshot `{meta['snapshot_id']}`, reference time T = {t:%Y-%m-%d %H:%M} UTC.",
    ]
    if result.unscored:
        names = ", ".join(f"{name} ({reason})" for name, reason in result.unscored.items())
        lines.append(f"- **Not scored:** {names}.")
    if result.issues:
        issues = "; ".join(f"line {i.line_no} `{i.line}` ({i.reason})" for i in result.issues)
        lines.append(f"- **Requirement lines not used:** {issues}.")
    lines += [
        "",
        "**Risk score:** a score of X means the package's combined risk is higher than X% of "
        "the baseline packages. Each signal (maintenance, Python 3.12 compatibility, known "
        "vulnerabilities, dependencies) adds more the rarer its value is in the baseline. It "
        "is a relative ranking, not a probability of failure. Method: `RISK_MODEL.md`; every "
        "signal value, placement and flag: `results.json`.",
        "",
        "Signal ids used in the agent's rationales: "
        + "; ".join(f"{s} {label}" for s, label in _SIGNAL_IDS.items())
        + ".",
        "",
    ]
    return lines


def _ranking(result: AnalysisResult) -> list[str]:
    lines = [
        "## Dependency ranking",
        "",
        "| Rank | Package | Effective version | Risk score | Main risk factors |",
        "|---:|---|---|---:|---|",
    ]
    for i, p in enumerate(result.ranked, 1):
        version = p.signals.effective_version or f"none (newest: {p.signals.reference_version})"
        lines.append(f"| {i} | {p.name} | {version} | {p.final_score:.2f} | {_main_factors(p)} |")
    return [*lines, ""]


def _action(out: dict) -> str:
    action, target = out.get("action"), out.get("target")
    if action == "replace":
        kind = _REPLACEMENT_KIND.get(str(out.get("replacement_type")), "package")
        return f"replace with `{target}` ({kind})"
    if action == "do_nothing":
        return "do nothing"
    return f"{action} to `{target}`"


def _recommendations(
    result: AnalysisResult, recommendations: Sequence[Recommendation] | None
) -> list[str]:
    if recommendations is None:
        return ["## Top recommendations", "", "Not run (`--no-llm`).", ""]
    ranks = {p.name: i for i, p in enumerate(result.ranked, 1)}
    lines = [
        f"## Top {len(recommendations)} recommendations",
        "",
        "Produced by the agent; code validated every fact it cites against the PyPI data "
        "(facts validated; suitability not verified). The cited evidence and the agent's "
        "tool calls are in `results.json`.",
        "",
    ]
    for rec in recommendations:
        out = dict(rec.output or {})
        heading = f"### {ranks.get(rec.package, '-')}. {rec.package}"
        if not out:
            lines += [
                f"{heading}: no validated recommendation",
                "",
                f"Unresolved after {rec.attempts} attempts; the errors are in `results.json`.",
                "",
            ]
            continue
        lines += [f"{heading}: {_action(out)}", "", str(out.get("rationale", "")), ""]
        if out.get("suitability_assumptions"):
            assumptions = "; ".join(a.strip().rstrip(".") for a in out["suitability_assumptions"])
            lines += [f"Assumptions: {assumptions}.", ""]
    return lines


def render_report(result: AnalysisResult, recommendations: Sequence[Recommendation] | None) -> str:
    """The Markdown report (deterministic for the same inputs)."""
    lines = [
        "# Dependency risk report",
        "",
        *_summary(result),
        *_ranking(result),
        *_recommendations(result, recommendations),
    ]
    return "\n".join(lines).rstrip() + "\n"

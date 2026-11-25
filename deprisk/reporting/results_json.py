"""results.json (SPEC §16): the machine-readable output of a run.

Deterministic: keys sorted, floats rounded to ``ROUND_DECIMALS``, no wall-clock time
(only ``T`` from the snapshot). LLM output is recorded here, not reproduced.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from deprisk import config
from deprisk.agent.models import Recommendation
from deprisk.risk.models import AnalysisResult, PackageScore


def _rounded(value: Any) -> Any:
    """Round every float in a JSON-like structure (results must compare exactly)."""
    if isinstance(value, float):
        return round(value, config.ROUND_DECIMALS) + 0.0
    if isinstance(value, dict):
        return {k: _rounded(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_rounded(v) for v in value]
    return value


def package_entry(rank: int, score: PackageScore) -> dict[str, Any]:
    """One ranked package: versions, per-signal value/q/contribution, totals, flags, evidence."""
    sig, placement = score.signals, score.placement
    return {
        "rank": rank,
        "name": score.name,
        "specifier": sig.evidence.get("specifier", ""),
        "effective_version": sig.effective_version,
        "reference_version": sig.reference_version,
        "final_score": score.final_score,
        "total": placement.total,
        "categories": dict(placement.categories),
        "signals": {
            s: {
                "value": sig.values[s],
                "q": placement.q[s],
                "contribution": placement.contributions[s],
                "partial": s in sig.partial,
            }
            for s in config.SIGNALS
        },
        "beyond_baseline_range": list(placement.beyond_range),
        "flags": [f.model_dump(mode="json") for f in score.flags],
        "evidence": dict(sig.evidence),
    }


def build_results(
    result: AnalysisResult, recommendations: Sequence[Recommendation] | None
) -> dict[str, Any]:
    """The full results document as plain JSON-ready data."""
    models = sorted({r.model for r in recommendations or () if r.model})
    run = {**result.run_meta, "model": ", ".join(models) or None}
    return _rounded(
        {
            "run": run,
            "packages": [package_entry(i, s) for i, s in enumerate(result.ranked, 1)],
            "unscored": dict(result.unscored),
            "issues": [i.model_dump(mode="json") for i in result.issues],
            "baseline_summary": dict(result.baseline_summary),
            "recommendations": None
            if recommendations is None
            else [r.model_dump(mode="json") for r in recommendations],
        }
    )


def write_results(
    result: AnalysisResult, recommendations: Sequence[Recommendation] | None, path: Path
) -> None:
    """Write results.json (sorted keys, 2-space indent, trailing newline)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(build_results(result, recommendations), sort_keys=True, indent=2)
    path.write_text(text + "\n", encoding="utf-8")

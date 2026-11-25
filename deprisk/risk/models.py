"""Risk-model types: signals, placements, scores and analysis results (PLAN.md interfaces)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from deprisk.data.models import FrozenModel, ParseIssue


class UnscorableError(Exception):
    """A package has no valid reference version (SPEC §11); ``reason`` says why."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class PackageSignals(FrozenModel):
    """Raw signal values of one package at ``T``.

    ``values[s] is None`` = unknown (neutral contribution); ``partial`` = signals whose
    value is a conservative lower bound because some entries were malformed.
    """

    name: str
    effective_version: str | None
    reference_version: str
    values: Mapping[str, float | None]
    partial: frozenset[str]
    evidence: Mapping[str, Any]


class Placement(FrozenModel):
    """Placement of a package's signals on the baseline distributions (SPEC §10)."""

    q: Mapping[str, float]
    contributions: Mapping[str, float]
    categories: Mapping[str, float]
    total: float
    beyond_range: tuple[str, ...]


class Flag(FrozenModel):
    """A display-only critical flag with its evidence (SPEC §10.4)."""

    code: str
    evidence: Mapping[str, Any]


class PackageScore(FrozenModel):
    """Everything the report shows about one scored package."""

    name: str
    signals: PackageSignals
    placement: Placement
    final_score: float
    flags: tuple[Flag, ...]


class Baseline(FrozenModel):
    """The scored top-5,000 baseline: per-package results and reference distributions."""

    signals: Mapping[str, PackageSignals]
    scores: Mapping[str, PackageScore]
    distributions: Mapping[str, Any]  # signal -> scoring.Distribution (avoids an import cycle)
    sorted_totals: tuple[float, ...]
    exclusions: Mapping[str, int]
    n: int


class AnalysisResult(FrozenModel):
    """Phase B output: ranked targets, unscored targets with reasons, and the summary."""

    ranked: tuple[PackageScore, ...]
    unscored: Mapping[str, str]
    issues: tuple[ParseIssue, ...]
    baseline_summary: Mapping[str, Any]
    run_meta: Mapping[str, Any]

"""Critical flags: display only, each with its evidence (SPEC §10.4)."""

from __future__ import annotations

from typing import Any

from deprisk.config import SIGNALS
from deprisk.risk.flags import critical_flags
from deprisk.risk.models import Flag, PackageSignals, Placement

PLACEMENT = Placement(q={}, contributions={}, categories={}, total=0.0, beyond_range=())


def sig(
    effective: str | None = "1.0", evidence: dict[str, Any] | None = None, partial=(), **values
) -> PackageSignals:
    full = {s: 0.0 for s in SIGNALS}
    full.update(values)
    return PackageSignals(
        name="pkg",
        effective_version=effective,
        reference_version="1.0",
        values=full,
        partial=frozenset(partial),
        evidence={
            "missing": [],
            "advisories": [],
            "malformed_requires_dist": [],
            **(evidence or {}),
        },
    )


def codes(flags: tuple[Flag, ...]) -> list[str]:
    return [f.code for f in flags]


def by_code(flags: tuple[Flag, ...], code: str) -> Flag:
    return next(f for f in flags if f.code == code)


def test_no_flags_for_a_clean_package() -> None:
    assert critical_flags(sig(), PLACEMENT) == ()


def test_no_eligible_version() -> None:
    flags = critical_flags(sig(effective=None, S4=5, S5=2), PLACEMENT)
    assert codes(flags) == ["no_eligible_version"]
    assert by_code(flags, "no_eligible_version").evidence == {"reference_version": "1.0", "S5": 2}


def test_python_fallback() -> None:
    flags = critical_flags(sig(S4=4, S5=1), PLACEMENT)
    assert codes(flags) == ["python_fallback", "sdist_only"]
    assert by_code(flags, "python_fallback").evidence == {"effective_version": "1.0", "S4": 4}


def test_sdist_only() -> None:
    flags = critical_flags(sig(S5=1), PLACEMENT)
    assert by_code(flags, "sdist_only").evidence == {"effective_version": "1.0", "S5": 1}


def test_unfixed_and_fixed_advisories() -> None:
    advisories = [
        {"id": "GHSA-a", "aliases": ["CVE-1"], "fixed_in": []},
        {"id": "GHSA-b", "aliases": [], "fixed_in": ["1.1"]},
    ]
    flags = critical_flags(sig(S6=2, evidence={"advisories": advisories}), PLACEMENT)
    assert codes(flags) == ["advisory_with_fix", "unfixed_advisory"]
    assert by_code(flags, "unfixed_advisory").evidence == {
        "version": "1.0",
        "advisories": [advisories[0]],
    }
    assert by_code(flags, "advisory_with_fix").evidence == {
        "version": "1.0",
        "advisories": [advisories[1]],
    }


def test_missing_field_flags() -> None:
    flags = critical_flags(
        sig(S6=None, S7=None, evidence={"missing": ["vulnerabilities", "requires_dist"]}), PLACEMENT
    )
    assert codes(flags) == ["missing:requires_dist", "missing:vulnerabilities"]
    assert by_code(flags, "missing:vulnerabilities").evidence == {
        "version": "1.0",
        "field": "vulnerabilities",
        "value": None,
    }


def test_malformed_requires_dist_flagged_as_missing_with_entries() -> None:
    flags = critical_flags(
        sig(S7=2, partial=("S7",), evidence={"malformed_requires_dist": ["bad !!"]}), PLACEMENT
    )
    assert codes(flags) == ["missing:requires_dist"]
    assert by_code(flags, "missing:requires_dist").evidence == {
        "version": "1.0",
        "field": "requires_dist",
        "malformed_entries": ["bad !!"],
    }


def test_beyond_baseline_range() -> None:
    placement = PLACEMENT.model_copy(update={"beyond_range": ("S1",)})
    flags = critical_flags(sig(S1=9999.0), placement)
    assert codes(flags) == ["beyond_baseline_range"]
    assert by_code(flags, "beyond_baseline_range").evidence == {"signals": {"S1": 9999.0}}


def test_flags_do_not_change_score() -> None:
    """Flags are derived from signals and placement; computing them leaves both unchanged."""
    s = sig(effective=None, S4=5, S5=2, S6=None, evidence={"missing": ["vulnerabilities"]})
    before = (s.model_dump(), PLACEMENT.model_dump())
    assert critical_flags(s, PLACEMENT)
    assert (s.model_dump(), PLACEMENT.model_dump()) == before

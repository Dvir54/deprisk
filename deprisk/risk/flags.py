"""Critical flags (SPEC §10.4): shown next to the score, never part of it.

Each flag carries the evidence behind it (version, field, value), so the report and
the agent can cite it. Flags are sorted by code for deterministic output.
"""

from __future__ import annotations

from typing import Any

from deprisk.risk.models import Flag, PackageSignals, Placement


def critical_flags(sig: PackageSignals, placement: Placement) -> tuple[Flag, ...]:
    """Every §10.4 flag that applies to a scored package, sorted by code."""
    values = sig.values
    ev = sig.evidence
    flags: list[Flag] = []

    if values["S5"] == 2:
        flags.append(
            Flag(
                code="no_eligible_version",
                evidence={"reference_version": sig.reference_version, "S5": 2},
            )
        )
    if values["S4"] == 4:
        flags.append(
            Flag(
                code="python_fallback",
                evidence={"effective_version": sig.effective_version, "S4": 4},
            )
        )
    if values["S5"] == 1:
        flags.append(
            Flag(code="sdist_only", evidence={"effective_version": sig.effective_version, "S5": 1})
        )

    # Per vulnerability (deduplicated advisory group): fixed if any member names a fix.
    groups: list[dict[str, Any]] = ev.get("advisory_groups", [])
    unfixed = [g for g in groups if not g["fixed_in"]]
    fixed = [g for g in groups if g["fixed_in"]]
    if unfixed:
        flags.append(
            Flag(
                code="unfixed_advisory",
                evidence={"version": sig.reference_version, "vulnerabilities": unfixed},
            )
        )
    if fixed:
        flags.append(
            Flag(
                code="advisory_with_fix",
                evidence={"version": sig.reference_version, "vulnerabilities": fixed},
            )
        )

    for field in ev.get("missing", []):
        flags.append(
            Flag(
                code=f"missing:{field}",
                evidence={"version": sig.reference_version, "field": field, "value": None},
            )
        )
    malformed = ev.get("malformed_requires_dist", [])
    if malformed:  # §11 policy: a malformed entry is missing information about that dependency
        flags.append(
            Flag(
                code="missing:requires_dist",
                evidence={
                    "version": sig.reference_version,
                    "field": "requires_dist",
                    "malformed_entries": malformed,
                },
            )
        )

    if placement.beyond_range:
        flags.append(
            Flag(
                code="beyond_baseline_range",
                evidence={"signals": {s: values[s] for s in placement.beyond_range}},
            )
        )
    return tuple(sorted(flags, key=lambda f: f.code))

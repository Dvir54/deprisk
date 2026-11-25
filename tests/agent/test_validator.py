"""Pure recommendation validator (SPEC §15, AC6): contexts built from literals, no network."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from deprisk.agent.models import ToolCall, ValidationContext
from deprisk.agent.validator import validate

T = datetime(2026, 11, 25, tzinfo=UTC)


def signal(value: float | None, contribution: float) -> dict[str, Any]:
    return {"value": value, "q": 0.5, "contribution": contribution, "partial": False}


def profile(**overrides: Any) -> dict[str, Any]:
    """pkg>=1.0, effective 1.4 (sdist only), no advisories; top-2 signals are S1 and S2."""
    base = {
        "name": "pkg",
        "specifier": ">=1.0",
        "effective_version": "1.4",
        "reference_version": "1.4",
        "final_score": 90.0,
        "total": 7.0,
        "signals": {
            "S1": signal(1000.0, 3.0),
            "S2": signal(0, 1.5),
            "S4": signal(0, 0.0),
            "S5": signal(1, 0.2),
            "S6": signal(0, 0.0),
            "S7": signal(3, 0.7),
        },
        "beyond_baseline_range": [],
        "flags": [{"code": "sdist_only", "evidence": {"effective_version": "1.4", "S5": 1}}],
        "evidence": {
            "advisories": [],
            "advisory_groups": [],
            "missing": [],
            "last_upload": "2023-01-01T00:00:00+00:00",
        },
    }
    return {**base, **overrides}


VULN_GROUP = {"ids": ["GHSA-a", "PYSEC-a"], "aliases": ["CVE-a"], "fixed_in": []}
VULN_PROFILE = profile(
    signals={**profile()["signals"], "S6": signal(1, 6.0)},  # top-2: S6, S1
    flags=[
        {"code": "sdist_only", "evidence": {"effective_version": "1.4", "S5": 1}},
        {
            "code": "unfixed_advisory",
            "evidence": {"version": "1.4", "vulnerabilities": [VULN_GROUP]},
        },
    ],
    evidence={
        **profile()["evidence"],
        "advisories": [
            {"id": "PYSEC-a", "aliases": ["CVE-a"], "fixed_in": []},
            {"id": "GHSA-a", "aliases": ["CVE-a"], "fixed_in": []},
        ],
        "advisory_groups": [VULN_GROUP],
    },
)

REQUIREMENT = {
    "specifier": ">=1.0",
    "line": "pkg>=1.0",
    "allowed_versions": 4,
    "floor_version": "1.0",
    "allowed_majors": [1],
    "spec_spans_major": False,
    "floor_vulnerabilities": [
        {"id": "PYSEC-9", "aliases": ["CVE-9", "GHSA-9"], "fixed_in": ["1.2"]}
    ],
    "spec_allows_advisories": True,
}
ELIGIBLE = {
    "specifier": ">=1.0",
    "effective_version": "1.4",
    "oldest_allowed_version": "1.0",
    "versions": [
        {"version": "1.4", "allowed": True, "eligible": True},
        {"version": "1.2", "allowed": True, "eligible": True},
        {"version": "1.1", "allowed": True, "eligible": False},
        {"version": "1.0", "allowed": True, "eligible": True},
        {"version": "0.9", "allowed": False, "eligible": True},
    ],
}


def details(version: str, **overrides: Any) -> dict[str, Any]:
    base = {
        "version": version,
        "is_final": True,
        "yanked": False,
        "satisfies_specifier": True,
        "eligible": True,
        "vulnerabilities": [],
    }
    return {**base, **overrides}


def call(
    call_id: str,
    name: str,
    output: dict[str, Any],
    origin: str = "agent",
    args: dict[str, Any] | None = None,
    package: str = "pkg",
) -> ToolCall:
    return ToolCall(
        id=call_id,
        package=package,
        name=name,
        args=args or {},
        output=output,
        source="snapshot",
        origin=origin,
        fetched_at=T,
    )


def agent_calls(prof: dict[str, Any] | None = None, req: dict | None = None) -> list[ToolCall]:
    return [
        call("call_1", "get_package_profile", prof or profile()),
        call("call_2", "get_requirement", req or REQUIREMENT),
    ]


def version_checks(version: str, **detail_overrides: Any) -> list[ToolCall]:
    """The validation calls collect_validation_evidence makes for upgrade/pin."""
    return [
        call("call_3", "find_eligible_versions", ELIGIBLE, origin="validation"),
        call(
            "call_4",
            "get_version_details",
            details(version, **detail_overrides),
            origin="validation",
            args={"version": version},
        ),
    ]


def candidate(name: str, **overrides: Any) -> ToolCall:
    output = {
        "name": name,
        "is_stdlib_module": False,
        "exists": True,
        "in_snapshot": True,
        "valid": True,
        "reason": None,
        "effective_version": "3.0",
        "reference_version": "3.0",
        "final_score": 40.0,
        "total": 2.0,
        "flags": [],
        "beyond_baseline_range": [],
        **overrides,
    }
    return call("call_3", "lookup_candidate", output, origin="validation", args={"name": name})


def ctx(calls: list[ToolCall], prof: dict[str, Any] | None = None) -> ValidationContext:
    return ValidationContext(
        package="pkg", profile=prof or profile(), specifier=">=1.0", calls=tuple(calls), t=T
    )


def evidence(call_id: str, field: str, value: Any) -> dict[str, Any]:
    return {"call_id": call_id, "field": field, "value": value}


ADVISORY_EVIDENCE = evidence("call_2", "floor_vulnerabilities[0].id", "PYSEC-9")


def rec(action: str, target: str = "", **overrides: Any) -> dict[str, Any]:
    base = {
        "action": action,
        "target": target,
        "replacement_type": "none",
        "finding": "spec_allows_advisories",
        "rationale": "The allowed range includes a release with a known advisory.",
        "evidence": [ADVISORY_EVIDENCE],
        "suitability_assumptions": [],
        "uncertainties": [],
        "confidence": "high",
    }
    return {**base, **overrides}


def replace_rec(target: str, kind: str, **overrides: Any) -> dict[str, Any]:
    defaults = {
        "replacement_type": kind,
        "finding": "sdist_only",
        "evidence": [evidence("call_1", "flags[0].code", "sdist_only")],
        "suitability_assumptions": ["Same public API for the functions this service uses."],
    }
    return rec("replace", target, **{**defaults, **overrides})


def do_nothing_rec(**overrides: Any) -> dict[str, Any]:
    defaults = {
        "finding": "S1",
        "evidence": [
            evidence("call_1", "signals.S1.value", 1000),
            evidence("call_1", "signals.S2.value", 0),
        ],
    }
    return rec("do_nothing", **{**defaults, **overrides})


def assert_rejected(errors: list[str], *fragments: str) -> None:
    assert errors, "expected the recommendation to be rejected"
    text = " | ".join(errors).lower()
    for fragment in fragments:
        assert fragment.lower() in text, (fragment, errors)


# --- accepted ------------------------------------------------------------------------


def test_accepts_valid_upgrade() -> None:
    assert validate(rec("upgrade", ">=1.2"), ctx(agent_calls() + version_checks("1.2"))) == []


def test_accepts_valid_pin() -> None:
    assert validate(rec("pin", "==1.2"), ctx(agent_calls() + version_checks("1.2"))) == []


def test_accepts_valid_stdlib_replace() -> None:
    assert validate(replace_rec("enum", "stdlib"), ctx(agent_calls())) == []


def test_accepts_valid_pypi_replace() -> None:
    assert validate(replace_rec("newlib", "pypi"), ctx([*agent_calls(), candidate("newlib")])) == []


def test_accepts_valid_do_nothing() -> None:
    assert validate(do_nothing_rec(), ctx(agent_calls())) == []


def test_accepts_numeric_value_written_as_text() -> None:
    item = evidence("call_1", "signals.S1.value", "1000.0")
    assert (
        validate(
            do_nothing_rec(evidence=[item, *do_nothing_rec()["evidence"][1:]]), ctx(agent_calls())
        )
        == []
    )


# --- AC6 rejections ------------------------------------------------------------------


def test_rejects_unknown_version() -> None:
    calls = agent_calls() + version_checks("1.2")
    calls[-1] = call(
        "call_4", "get_version_details", {"error": "no release"}, "validation", {"version": "1.2"}
    )
    assert_rejected(validate(rec("upgrade", ">=1.2"), ctx(calls)), "does not exist")


def test_rejects_yanked_version() -> None:
    errors = validate(
        rec("upgrade", ">=1.2"), ctx(agent_calls() + version_checks("1.2", yanked=True))
    )
    assert_rejected(errors, "yanked")


def test_rejects_ineligible_version() -> None:
    errors = validate(
        rec("upgrade", ">=1.2"), ctx(agent_calls() + version_checks("1.2", eligible=False))
    )
    assert_rejected(errors, "not eligible")


def test_rejects_prerelease_and_out_of_spec_upgrade() -> None:
    errors = validate(
        rec("upgrade", ">=1.2"),
        ctx(agent_calls() + version_checks("1.2", is_final=False, satisfies_specifier=False)),
    )
    assert_rejected(errors, "not a final release", "current specifier")


def test_rejects_upgrade_not_raising_floor() -> None:
    errors = validate(rec("upgrade", ">=1.0"), ctx(agent_calls() + version_checks("1.0")))
    assert_rejected(errors, "raise the current floor")


def test_rejects_nonexistent_package() -> None:
    calls = [*agent_calls(), candidate("nopkg", exists=False, valid=False, reason="not found")]
    assert_rejected(validate(replace_rec("nopkg", "pypi"), ctx(calls)), "does not exist")


def test_rejects_riskier_replacement() -> None:
    calls = [*agent_calls(), candidate("newlib", final_score=95.0)]
    assert_rejected(validate(replace_rec("newlib", "pypi"), ctx(calls)), "not lower")


@pytest.mark.parametrize("flag", ["no_eligible_version", "python_fallback", "unfixed_advisory"])
def test_rejects_replacement_with_critical_flag(flag: str) -> None:
    calls = [*agent_calls(), candidate("newlib", flags=[flag])]
    assert_rejected(validate(replace_rec("newlib", "pypi"), ctx(calls)), flag)


def test_rejects_candidate_without_reference_version_as_of_t() -> None:
    calls = [*agent_calls(), candidate("newlib", valid=False, reason="no files")]
    assert_rejected(validate(replace_rec("newlib", "pypi"), ctx(calls)), "no files")


def test_rejects_unknown_stdlib_module() -> None:
    assert_rejected(validate(replace_rec("notamodule", "stdlib"), ctx(agent_calls())), "stdlib")


def test_rejects_empty_evidence() -> None:
    errors = validate(
        rec("upgrade", ">=1.2", evidence=[]), ctx(agent_calls() + version_checks("1.2"))
    )
    assert_rejected(errors, "evidence")


@pytest.mark.parametrize(
    ("item", "fragment"),
    [
        (evidence("call_99", "floor_vulnerabilities[0].id", "PYSEC-9"), "unknown call"),
        (evidence("call_2", "floor_vulnerabilities[0].id", "PYSEC-1234"), "does not match"),
        (evidence("call_2", "floor_vulnerabilities[5].id", "PYSEC-9"), "not found"),
        (evidence("call_2", "no_such_field", "x"), "not found"),
    ],
)
def test_rejects_fabricated_evidence(item: dict[str, Any], fragment: str) -> None:
    errors = validate(
        rec("upgrade", ">=1.2", evidence=[ADVISORY_EVIDENCE, item]),
        ctx(agent_calls() + version_checks("1.2")),
    )
    assert_rejected(errors, fragment)


def test_rejects_evidence_for_another_package() -> None:
    other = call("call_7", "get_requirement", REQUIREMENT, package="other")
    item = evidence("call_7", "floor_vulnerabilities[0].id", "PYSEC-9")
    errors = validate(
        rec("upgrade", ">=1.2", evidence=[item]),
        ctx([*agent_calls(), other, *version_checks("1.2")]),
    )
    assert_rejected(errors, "another package")


def test_rejects_evidence_unrelated_to_finding() -> None:
    errors = validate(
        rec("upgrade", ">=1.2", evidence=[evidence("call_2", "specifier", ">=1.0")]),
        ctx(agent_calls() + version_checks("1.2")),
    )
    assert_rejected(errors, "supports the finding")


@pytest.mark.parametrize("finding", ["S3", "unfixed_advisory", "S7", "spec_spans_major", ""])
def test_rejects_nonexistent_finding(finding: str) -> None:
    errors = validate(
        rec("upgrade", ">=1.2", finding=finding), ctx(agent_calls() + version_checks("1.2"))
    )
    assert_rejected(errors, "finding")


def test_rejects_action_not_addressing_finding() -> None:
    upgrade_s1 = rec(
        "upgrade", ">=1.2", finding="S1", evidence=[evidence("call_1", "signals.S1.value", 1000.0)]
    )
    assert_rejected(
        validate(upgrade_s1, ctx(agent_calls() + version_checks("1.2"))), "does not address"
    )
    replace_s16 = replace_rec(
        "enum", "stdlib", finding="spec_allows_advisories", evidence=[ADVISORY_EVIDENCE]
    )
    assert_rejected(validate(replace_s16, ctx(agent_calls())), "does not address")
    do_nothing_flag = do_nothing_rec(finding="sdist_only")
    assert_rejected(validate(do_nothing_flag, ctx(agent_calls())), "does not address")


def test_rejects_upgrade_when_finding_stays_in_allowed_versions() -> None:
    """sdist_only is about 1.4, which >=1.2 still allows."""
    sdist = rec(
        "upgrade",
        ">=1.2",
        finding="sdist_only",
        evidence=[evidence("call_1", "flags[0].code", "sdist_only")],
    )
    assert_rejected(
        validate(sdist, ctx(agent_calls() + version_checks("1.2"))), "excluded versions"
    )


def test_rejects_upgrade_whose_target_has_the_cited_vulnerability_by_alias() -> None:
    """PYSEC-9 is cited; V lists the same vulnerability as GHSA-9 (an alias of PYSEC-9)."""
    v_vulns = [{"id": "GHSA-9", "aliases": ["CVE-9"], "fixed_in": ["1.5"]}]
    errors = validate(
        rec("upgrade", ">=1.2"), ctx(agent_calls() + version_checks("1.2", vulnerabilities=v_vulns))
    )
    assert_rejected(errors, "cited vulnerability")


def test_rejects_upgrade_when_target_vulnerabilities_unknown() -> None:
    errors = validate(
        rec("upgrade", ">=1.2"), ctx(agent_calls() + version_checks("1.2", vulnerabilities=None))
    )
    assert_rejected(errors, "missing evidence")


def test_rejects_do_nothing_with_advisories() -> None:
    calls = [call("call_1", "get_package_profile", VULN_PROFILE), agent_calls()[1]]
    item = evidence("call_1", "signals.S6.value", 1)
    errors = validate(
        do_nothing_rec(finding="S6", evidence=[item, do_nothing_rec()["evidence"][0]]),
        ctx(calls, VULN_PROFILE),
    )
    assert_rejected(errors, "advisories")


def test_rejects_do_nothing_without_effective_version() -> None:
    prof = profile(effective_version=None)
    calls = [call("call_1", "get_package_profile", prof), agent_calls()[1]]
    assert_rejected(validate(do_nothing_rec(), ctx(calls, prof)), "no effective version")


def test_rejects_do_nothing_not_naming_every_top_signal() -> None:
    only_s1 = do_nothing_rec(evidence=[evidence("call_1", "signals.S1.value", 1000)])
    assert_rejected(validate(only_s1, ctx(agent_calls())), "S2")


def test_rejects_replace_without_suitability_assumptions() -> None:
    errors = validate(replace_rec("enum", "stdlib", suitability_assumptions=[]), ctx(agent_calls()))
    assert_rejected(errors, "suitability_assumptions")


def test_rejects_pin_on_major_span_alone() -> None:
    spans = {**REQUIREMENT, "allowed_majors": [1, 2], "spec_spans_major": True}
    pin = rec(
        "pin",
        "<2.0",
        finding="spec_spans_major",
        evidence=[evidence("call_2", "spec_spans_major", True)],
    )
    calls = agent_calls(req=spans) + version_checks("1.4")
    assert_rejected(validate(pin, ctx(calls)), "major")


def test_rejects_target_that_is_not_concrete() -> None:
    calls = agent_calls() + version_checks("1.2")
    assert_rejected(validate(rec("upgrade", "latest"), ctx(calls)), "target")
    assert_rejected(validate(rec("pin", "~=1.2"), ctx(calls)), "target")
    assert_rejected(
        validate({**rec("upgrade", ">=1.2"), "action": "rewrite"}, ctx(calls)), "action"
    )
    assert_rejected(validate(replace_rec("", "pypi"), ctx(agent_calls())), "target")


def test_rejects_missing_validation_evidence() -> None:
    assert_rejected(validate(rec("upgrade", ">=1.2"), ctx(agent_calls())), "missing evidence")
    assert_rejected(validate(replace_rec("newlib", "pypi"), ctx(agent_calls())), "missing evidence")


# --- P1 ------------------------------------------------------------------------------


def test_rejects_evidence_citing_validation_call() -> None:
    item = evidence("call_4", "vulnerabilities", [])
    errors = validate(
        rec("upgrade", ">=1.2", evidence=[ADVISORY_EVIDENCE, item]),
        ctx(agent_calls() + version_checks("1.2")),
    )
    assert_rejected(errors, "validation")


def test_upgrade_accepted_when_citing_alias_of_advisory() -> None:
    """Citing the GHSA alias instead of the PYSEC id of the same vulnerability works."""
    item = evidence("call_2", "floor_vulnerabilities[0].aliases[1]", "GHSA-9")
    assert (
        validate(
            rec("upgrade", ">=1.2", evidence=[item]), ctx(agent_calls() + version_checks("1.2"))
        )
        == []
    )


def test_pin_below_excludes_ineligible_newer_versions() -> None:
    """A pin below a release that lost eligibility, citing that release's eligibility."""
    prof = profile(flags=[{"code": "python_fallback", "evidence": {"effective_version": "1.2"}}])
    elig = {
        **ELIGIBLE,
        "versions": [{"version": "2.0", "allowed": True, "eligible": False}, *ELIGIBLE["versions"]],
    }
    calls = [
        call("call_1", "get_package_profile", prof),
        call("call_2", "find_eligible_versions", elig),
        call("call_3", "find_eligible_versions", elig, origin="validation"),
        call("call_4", "get_version_details", details("1.4"), "validation", {"version": "1.4"}),
    ]
    pin = rec(
        "pin",
        "<2.0",
        finding="python_fallback",
        evidence=[evidence("call_2", "versions[0].eligible", False)],
    )
    assert validate(pin, ctx(calls, prof)) == []
    eligible_citation = rec(
        "pin",
        "<2.0",
        finding="python_fallback",
        evidence=[evidence("call_2", "versions[1].eligible", True)],
    )
    assert_rejected(validate(eligible_citation, ctx(calls, prof)), "excluded versions")

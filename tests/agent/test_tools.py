"""Agent tools: read-only views of the snapshot, live candidates as of T, call log (§13)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from packaging.specifiers import SpecifierSet

from deprisk import config
from deprisk.agent.tools import TOOL_SCHEMAS, AgentTools
from deprisk.data.models import Requirement, Snapshot
from deprisk.reporting.results_json import package_entry
from deprisk.risk.analysis import analyze
from deprisk.risk.baseline import build_baseline

LIVE_TIME = datetime(2026, 11, 26, 9, 30, tzinfo=UTC)
CLEAN = {"classifiers": [], "requires_dist": [], "vulnerabilities": []}
WHEEL = {"packagetype": "bdist_wheel", "filename": "target-2.0-py3-none-any.whl"}


def raw_file(filename: str, upload: str, packagetype: str = "sdist") -> dict[str, Any]:
    return {
        "filename": filename,
        "packagetype": packagetype,
        "upload_time_iso_8601": upload,
        "yanked": False,
        "requires_python": None,
    }


class LiveStub:
    """``fetch_live`` stand-in: canned PyPI JSON by (name, version); records requests."""

    def __init__(self, responses: dict[tuple[str, str | None], dict[str, Any]]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str | None]] = []

    def __call__(self, name: str, version: str | None) -> tuple[dict, datetime] | None:
        self.requests.append((name, version))
        body = self.responses.get((name, version))
        return None if body is None else (body, LIVE_TIME)


def newlib_responses(fixed_t: datetime) -> dict[tuple[str, str | None], dict[str, Any]]:
    """A live-only candidate: 2.0 before T, 3.0 uploaded after T (must be ignored)."""
    after_t = (fixed_t + timedelta(days=3)).isoformat()
    project = {
        "info": {"name": "newlib", "version": "3.0", **CLEAN},
        "last_serial": 7,
        "releases": {
            "2.0": [raw_file("newlib-2.0-py3-none-any.whl", "2026-10-01T00:00:00Z", "bdist_wheel")],
            "3.0": [raw_file("newlib-3.0-py3-none-any.whl", after_t, "bdist_wheel")],
        },
        "vulnerabilities": [],
    }
    version_2 = {"info": {"name": "newlib", "version": "2.0", **CLEAN}, "vulnerabilities": []}
    return {("newlib", None): project, ("newlib", "2.0"): version_2}


@pytest.fixture
def snap(mini_snapshot: Snapshot, make_record, make_snapshot) -> Snapshot:
    """The mini snapshot plus ``target`` (spec >=1.0): 1.0 has a fixed advisory, 1.5's
    metadata is not in the snapshot (live fetch), 2.0 is the clean reference version."""
    target = make_record(
        {
            "1.0": [{"upload_time": "2020-01-01T00:00:00+00:00"}],
            "1.5": [{"upload_time": "2022-01-01T00:00:00+00:00"}],
            "2.0": [{**WHEEL, "upload_time": "2026-06-01T00:00:00+00:00"}],
        },
        {
            "2.0": CLEAN,
            "1.0": {
                **CLEAN,
                "vulnerabilities": [{"id": "PYSEC-1", "aliases": ["CVE-1"], "fixed_in": ["1.5"]}],
            },
        },
        name="target",
    )
    records = {**mini_snapshot.records, "target": target}
    return make_snapshot(records, exclusions=dict(mini_snapshot.meta["exclusions"]))


REQS = {
    "target": Requirement(name="target", specifier=SpecifierSet(">=1.0"), line="target>=1.0"),
    "legacy": Requirement(name="legacy", specifier=SpecifierSet(""), line="legacy"),
}


@pytest.fixture
def make_tools(snap: Snapshot, fixed_t: datetime) -> Callable[..., AgentTools]:
    def build(live: LiveStub | None = None, snapshot: Snapshot = snap) -> AgentTools:
        result = analyze(snapshot, list(REQS.values()))
        profiles = {s.name: package_entry(i, s) for i, s in enumerate(result.ranked, 1)}
        return AgentTools(
            snapshot=snapshot,
            baseline=build_baseline(snapshot, fixed_t),
            profiles=profiles,
            requirements=REQS,
            fetch_live=live or LiveStub(newlib_responses(fixed_t)),
        )

    return build


# --- schemas -------------------------------------------------------------------------


def test_tool_schemas_are_strict_and_closed() -> None:
    names = {s["name"] for s in TOOL_SCHEMAS}
    assert names == {
        "get_package_profile",
        "get_release_history",
        "get_version_details",
        "find_eligible_versions",
        "lookup_candidate",
        "get_requirement",
    }
    for schema in TOOL_SCHEMAS:
        assert schema["strict"] is True
        assert schema["input_schema"]["type"] == "object"
        assert schema["input_schema"]["additionalProperties"] is False
        assert set(schema["input_schema"]["required"]) == set(schema["input_schema"]["properties"])


# --- P0 ------------------------------------------------------------------------------


def test_every_call_logged_with_source_origin_and_time(make_tools, snap: Snapshot) -> None:
    tools = make_tools()
    profile = tools.call("target", "get_package_profile", {})
    live = tools.call("target", "lookup_candidate", {"name": "newlib"})
    failed = tools.call("target", "get_version_details", {"version": "9.9"})
    check = tools.call("target", "find_eligible_versions", {}, origin="validation")

    assert tools.log == [profile, live, failed, check]
    assert len({c.id for c in tools.log}) == 4
    assert (profile.source, profile.origin) == ("snapshot", "agent")
    assert profile.fetched_at == snap.records["target"].fetched_at
    assert (live.source, live.fetched_at) == ("live", LIVE_TIME)
    assert (failed.source, failed.fetched_at) == ("local", None)
    assert "error" in failed.output
    assert check.origin == "validation"
    assert all(c.package == "target" for c in tools.log)
    assert profile.output["name"] == "target"


def test_unknown_package_returns_error_not_raise(make_tools) -> None:
    tools = make_tools()
    for name, args in [
        ("get_package_profile", {}),
        ("get_release_history", {}),
        ("get_version_details", {"version": "1.0"}),
        ("find_eligible_versions", {}),
        ("get_requirement", {}),
    ]:
        call = tools.call("nosuch", name, args)
        assert "error" in call.output, name
    assert "error" in tools.call("target", "no_such_tool", {}).output
    assert "error" in tools.call("target", "get_version_details", {}).output  # missing arg
    assert "error" in tools.call("target", "get_version_details", {"version": "1.0", "x": 1}).output
    assert len(tools.log) == 8


def test_tool_exception_becomes_error_output(make_tools) -> None:
    def broken(name: str, version: str | None) -> None:
        raise RuntimeError("connection reset")

    tools = make_tools(live=broken)
    call = tools.call("target", "lookup_candidate", {"name": "newlib"})
    assert "connection reset" in call.output["error"]


def test_lookup_candidate_snapshot_vs_live_as_of_t(make_tools, snap: Snapshot) -> None:
    live = LiveStub(newlib_responses(datetime(2026, 11, 25, tzinfo=UTC)))
    tools = make_tools(live=live)

    in_snapshot = tools.call("target", "lookup_candidate", {"name": "Fresh0"}).output
    assert in_snapshot["exists"] is True and in_snapshot["in_snapshot"] is True
    assert in_snapshot["valid"] is True
    assert in_snapshot["effective_version"] == "1.0"
    assert in_snapshot["final_score"] == pytest.approx(
        package_entry(1, _score(tools, "fresh0"))["final_score"]
    )

    out = tools.call("target", "lookup_candidate", {"name": "newlib"}).output
    assert out["exists"] is True and out["in_snapshot"] is False and out["valid"] is True
    assert out["reference_version"] == "2.0"  # 3.0 was uploaded after T
    assert out["effective_version"] == "2.0"
    assert ("newlib", "2.0") in live.requests  # reference != latest: version endpoint
    assert live.requests.count(("fresh0", None)) == 0  # snapshot candidates never fetched


def _score(tools: AgentTools, name: str):
    return tools.baseline.scores[name]


def test_lookup_candidate_missing_or_unplaceable(make_tools, fixed_t: datetime) -> None:
    only_after_t = {
        ("late", None): {
            "info": {"name": "late", "version": "1.0", **CLEAN},
            "releases": {
                "1.0": [
                    raw_file("late-1.0.tar.gz", (fixed_t + timedelta(days=1)).isoformat()),
                ]
            },
            "vulnerabilities": [],
        }
    }
    tools = make_tools(live=LiveStub(only_after_t))
    missing = tools.call("target", "lookup_candidate", {"name": "nope"}).output
    assert missing["exists"] is False and missing["valid"] is False
    late = tools.call("target", "lookup_candidate", {"name": "late"}).output
    assert late["exists"] is True and late["valid"] is False
    assert late["reason"] == "no files"


def test_lookup_candidate_reports_stdlib_module(make_tools) -> None:
    out = make_tools(live=LiveStub({})).call("target", "lookup_candidate", {"name": "enum"})
    assert out.output["is_stdlib_module"] is True
    out = make_tools(live=LiveStub({})).call("target", "lookup_candidate", {"name": "newlib"})
    assert out.output["is_stdlib_module"] is False


def test_get_version_details_snapshot_and_live(make_tools, fixed_t: datetime) -> None:
    v15 = {
        "info": {"name": "target", "version": "1.5", **CLEAN, "requires_dist": ["a", "b"]},
        "vulnerabilities": [],
    }
    live = LiveStub({("target", "1.5"): v15})
    tools = make_tools(live=live)

    old = tools.call("target", "get_version_details", {"version": "1.0"})
    assert old.source == "snapshot"
    assert old.output["vulnerabilities"] == [
        {"id": "PYSEC-1", "aliases": ["CVE-1"], "fixed_in": ["1.5"]}
    ]
    assert old.output["is_final"] is True and old.output["yanked"] is False
    assert old.output["eligible"] is True and old.output["satisfies_specifier"] is True

    mid = tools.call("target", "get_version_details", {"version": "1.5"})
    assert (mid.source, mid.fetched_at) == ("live", LIVE_TIME)
    assert mid.output["requires_dist"] == ["a", "b"]

    new = tools.call("target", "get_version_details", {"version": "2.0"}).output
    assert new["files"]["wheels"] == 1 and new["eligible_files"] == ["target-2.0-py3-none-any.whl"]


def test_get_version_details_metadata_unavailable(make_tools) -> None:
    out = make_tools(live=LiveStub({})).call("target", "get_version_details", {"version": "1.5"})
    assert out.output["vulnerabilities"] is None and out.output["requires_dist"] is None
    assert out.output["eligible"] is True  # file facts still come from the snapshot


def test_find_eligible_versions(make_tools) -> None:
    out = make_tools().call("target", "find_eligible_versions", {}).output
    assert out["specifier"] == ">=1.0"
    assert out["effective_version"] == "2.0"
    assert out["oldest_allowed_version"] == "1.0"
    assert out["versions"] == [
        {"version": "2.0", "allowed": True, "eligible": True},
        {"version": "1.5", "allowed": True, "eligible": True},
        {"version": "1.0", "allowed": True, "eligible": True},
    ]


def test_collect_evidence_for_upgrade_logs_version_details(make_tools, fixed_t) -> None:
    tools = make_tools()
    agent_call = tools.call("target", "get_package_profile", {})
    tools.call("legacy", "get_package_profile", {})  # another package: not in the context
    rec = {"action": "upgrade", "target": ">=1.5", "replacement_type": "none"}
    ctx = tools.collect_validation_evidence("target", rec)

    assert ctx.package == "target" and ctx.specifier == ">=1.0" and ctx.t == fixed_t
    assert ctx.profile["name"] == "target"
    assert ctx.calls[0] == agent_call
    validation = [c for c in ctx.calls if c.origin == "validation"]
    assert [(c.name, dict(c.args)) for c in validation] == [
        ("find_eligible_versions", {}),
        ("get_version_details", {"version": "1.5"}),
    ]
    assert all(c in tools.log for c in validation)  # evidence collection is logged too
    assert len(ctx.calls) == 3


def test_collect_evidence_per_action(make_tools) -> None:
    tools = make_tools()
    pin_below = tools.collect_validation_evidence("target", {"action": "pin", "target": "<2.0"})
    assert [dict(c.args) for c in pin_below.calls if c.name == "get_version_details"] == [
        {"version": "1.5"}  # the highest allowed version below the bound
    ]
    replace = tools.collect_validation_evidence(
        "target", {"action": "replace", "target": "newlib", "replacement_type": "pypi"}
    )
    assert [(c.name, dict(c.args)) for c in replace.calls if c.origin == "validation"] == [
        ("lookup_candidate", {"name": "newlib"})
    ]
    before = len(tools.log)
    tools.collect_validation_evidence(
        "target", {"action": "replace", "target": "enum", "replacement_type": "stdlib"}
    )
    tools.collect_validation_evidence("target", {"action": "do_nothing", "target": ""})
    tools.collect_validation_evidence("target", {"action": "upgrade", "target": "garbage"})
    assert len(tools.log) == before  # nothing to fetch, never raises


# --- P1 ------------------------------------------------------------------------------


def test_candidate_beyond_baseline_range_flagged(make_tools, fixed_t: datetime) -> None:
    responses = newlib_responses(fixed_t)
    many_deps = [f"dep{i}" for i in range(50)]  # more than any baseline package
    responses[("newlib", "2.0")] = {
        "info": {"name": "newlib", "version": "2.0", **CLEAN, "requires_dist": many_deps},
        "vulnerabilities": [],
    }
    out = make_tools(live=LiveStub(responses)).call(
        "target", "lookup_candidate", {"name": "newlib"}
    )
    assert "beyond_baseline_range" in out.output["flags"]
    assert out.output["beyond_baseline_range"] == ["S7"]


def test_history_truncated(make_tools, make_record, make_snapshot, monkeypatch) -> None:
    monkeypatch.setattr(config, "HISTORY_LIMIT", 3)
    tools = make_tools()
    out = tools.call("target", "get_release_history", {}).output
    assert out["totals"]["releases"] == 3 and out["truncated"] is False

    big = make_record({f"1.{i}": [{}] for i in range(10)}, {"1.9": CLEAN}, name="big")
    snapshot = make_snapshot({**tools.snapshot.records, "big": big})
    out = make_tools(snapshot=snapshot).call("big", "get_release_history", {}).output
    assert [r["version"] for r in out["releases"]] == ["1.9", "1.8", "1.7"]
    assert out["truncated"] is True and out["totals"]["releases"] == 10


def test_requirement_context_s16(make_tools, make_record, make_snapshot) -> None:
    out = make_tools().call("target", "get_requirement", {}).output
    assert out["specifier"] == ">=1.0" and out["line"] == "target>=1.0"
    assert out["floor_version"] == "1.0"
    assert out["allowed_majors"] == [1, 2] and out["spec_spans_major"] is True
    assert out["floor_vulnerabilities"][0]["id"] == "PYSEC-1"
    assert out["spec_allows_advisories"] is True

    legacy = make_tools().call("legacy", "get_requirement", {}).output
    assert legacy["spec_spans_major"] is False and legacy["floor_version"] == "2.6"
    assert legacy["spec_allows_advisories"] is True  # legacy 2.6 has an unfixed advisory

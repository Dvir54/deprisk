"""results.json: every SPEC §16 field, deterministic bytes, rounded floats."""

from __future__ import annotations

import json
from pathlib import Path

from packaging.specifiers import SpecifierSet

from deprisk.config import ROUND_DECIMALS, SIGNALS
from deprisk.data.models import ParseIssue, Requirement
from deprisk.reporting.results_json import write_results
from deprisk.risk.analysis import analyze

REQS = [
    Requirement(name=n, specifier=SpecifierSet(s), line=f"{n}{s}")
    for n, s in [("fresh0", ""), ("legacy", ">=2"), ("fallback", ""), ("beta", ""), ("absent", "")]
]
ISSUE = ParseIssue(line_no=9, line="-r more.txt", reason="unsupported option: not followed")


def result(mini_snapshot):
    return analyze(mini_snapshot, REQS, issues=[ISSUE])


def test_results_json_contains_section_16_fields(tmp_path: Path, mini_snapshot) -> None:
    path = tmp_path / "results.json"
    write_results(result(mini_snapshot), None, path)
    data = json.loads(path.read_text("utf-8"))

    assert data["run"] == {
        "snapshot_id": "test-snapshot",
        "T": mini_snapshot.meta["T"],
        "list_last_update": "2026-11-01 06:41:05",
        "baseline_n": 7,
        "config_hash": data["run"]["config_hash"],
        "snapshot_config_hash": "test",
        "model": None,
    }
    assert [p["name"] for p in data["packages"]] == ["legacy", "fallback", "fresh0"]
    legacy = data["packages"][0]
    assert legacy["rank"] == 1
    assert legacy["specifier"] == ">=2"
    assert (legacy["effective_version"], legacy["reference_version"]) == ("2.6", "2.6")
    assert set(legacy["signals"]) == set(SIGNALS)
    assert set(legacy["signals"]["S6"]) == {"value", "q", "contribution", "partial"}
    assert legacy["signals"]["S7"]["value"] is None
    assert set(legacy["categories"]) == {"maintenance", "compatibility", "security", "dependencies"}
    assert isinstance(legacy["total"], float) and isinstance(legacy["final_score"], float)
    assert {"unfixed_advisory", "sdist_only", "missing:requires_dist"} <= {
        f["code"] for f in legacy["flags"]
    }
    assert {"S3", "S8", "S9", "S10", "S14"} <= set(legacy["evidence"])
    assert data["unscored"] == {"absent": "not in snapshot", "beta": "only pre-releases"}
    assert data["issues"] == [
        {"line_no": 9, "line": "-r more.txt", "reason": "unsupported option: not followed"}
    ]
    assert data["baseline_summary"]["n"] == 7
    assert data["recommendations"] is None


def test_results_json_deterministic_and_rounded(tmp_path: Path, mini_snapshot) -> None:
    write_results(result(mini_snapshot), None, tmp_path / "a.json")
    write_results(result(mini_snapshot), None, tmp_path / "b.json")
    raw = (tmp_path / "a.json").read_bytes()
    assert raw == (tmp_path / "b.json").read_bytes()
    s1 = json.loads(raw)["packages"][0]["signals"]["S1"]["value"]
    assert s1 == round(s1, ROUND_DECIMALS)

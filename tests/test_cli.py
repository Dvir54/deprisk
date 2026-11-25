"""CLI entry point and exit codes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from deprisk import cli


def test_help_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "deprisk", "--help"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    for command in ("fetch", "snapshot", "analyze", "check-llm"):
        assert command in result.stdout


def test_runtime_is_python_312() -> None:
    assert sys.version_info[:2] == (3, 12)


def test_missing_key_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_PROFILE",
        "ANTHROPIC_FEDERATION_RULE_ID",
        "ANTHROPIC_IDENTITY_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    # The SDK's credential-profile lookup reads ANTHROPIC_CONFIG_DIR: point it at an empty dir.
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path))
    assert cli.main(["check-llm"]) == cli.EXIT_CONFIG


def test_invalid_effort_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPRISK_LLM_EFFORT", "extreme")
    assert cli.main(["check-llm"]) == cli.EXIT_CONFIG


# --- analyze (mini snapshot, no network) -------------------------------------------------


def write_inputs(tmp_path: Path, mini_snapshot, names: list[str]) -> tuple[Path, Path]:
    from deprisk.data.snapshot import save_snapshot

    snap = tmp_path / "snapshot.json.gz"
    save_snapshot(mini_snapshot, snap)
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("\n".join(names) + "\n", encoding="utf-8")
    return reqs, snap


def test_no_llm_runs_without_api_key(tmp_path: Path, mini_snapshot) -> None:
    """AC7: --no-llm needs no key and never imports the anthropic SDK."""
    reqs, snap = write_inputs(tmp_path, mini_snapshot, ["fresh0", "legacy", "fallback>=1"])
    out = tmp_path / "out"
    code = (
        "import sys\n"
        "from deprisk import cli\n"
        f"rc = cli.main(['analyze', {str(reqs)!r}, '--snapshot', {str(snap)!r}, "
        f"'--out', {str(out)!r}, '--no-llm'])\n"
        "assert 'anthropic' not in sys.modules, 'anthropic was imported'\n"
        "sys.exit(rc)\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False
    )
    assert result.returncode == 0, result.stderr
    assert (out / "results.json").is_file()
    assert (out / "REPORT.md").is_file()


def test_cli_missing_target_exits_1_and_lists_it(tmp_path: Path, mini_snapshot) -> None:
    reqs, snap = write_inputs(tmp_path, mini_snapshot, ["fresh0", "not-there"])
    out = tmp_path / "out"
    rc = cli.main(["analyze", str(reqs), "--snapshot", str(snap), "--out", str(out), "--no-llm"])
    assert rc == cli.EXIT_INVALID_RUN
    results = json.loads((out / "results.json").read_text("utf-8"))  # outputs are still written
    assert results["unscored"] == {"not-there": "not in snapshot"}
    assert "**Not scored:** not-there (not in snapshot)." in (out / "REPORT.md").read_text("utf-8")


def test_missing_snapshot_exits_2(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("six\n", encoding="utf-8")
    rc = cli.main(["analyze", str(reqs), "--snapshot", str(tmp_path / "none.json.gz"), "--no-llm"])
    assert rc == cli.EXIT_CONFIG


def _no_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path))


def test_analyze_with_llm_without_credentials_exits_2(
    tmp_path: Path, mini_snapshot, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_credentials(monkeypatch, tmp_path)
    reqs, snap = write_inputs(tmp_path, mini_snapshot, ["fresh0"])
    rc = cli.main(["analyze", str(reqs), "--snapshot", str(snap), "--out", str(tmp_path / "o")])
    assert rc == cli.EXIT_CONFIG


class _AgentStub:
    """An SDK-shaped client that answers every request with one scripted ``Message``."""

    def __init__(self, submission: dict | None) -> None:
        from types import SimpleNamespace

        from anthropic.types import Message

        if submission is None:
            content = [{"type": "text", "text": "No recommendation."}]
            stop = "end_turn"
        else:
            content = [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "submit_recommendation",
                    "input": submission,
                }
            ]
            stop = "tool_use"
        self.response = Message.model_validate(
            {
                "id": "m",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-5-5",
                "stop_reason": stop,
                "stop_sequence": None,
                "content": content,
                "usage": {"input_tokens": 10, "output_tokens": 2},
            }
        )
        self.messages = SimpleNamespace(create=lambda **_: self.response)


def _legacy_submission(mini_snapshot) -> dict:
    from packaging.specifiers import SpecifierSet

    from deprisk.data.models import Requirement
    from deprisk.reporting.results_json import package_entry
    from deprisk.risk.analysis import analyze

    req = Requirement(name="legacy", specifier=SpecifierSet(""), line="legacy")
    profile = package_entry(1, analyze(mini_snapshot, [req]).ranked[0])
    index = [f["code"] for f in profile["flags"]].index("sdist_only")
    return {
        "action": "replace",
        "target": "enum",
        "replacement_type": "stdlib",
        "finding": "sdist_only",
        "rationale": "Only an sdist is published.",
        "evidence": [{"call_id": "call_1", "field": f"flags[{index}].code", "value": "sdist_only"}],
        "suitability_assumptions": ["Only the enum API is used."],
        "uncertainties": [],
        "confidence": "medium",
    }


@pytest.mark.parametrize(("validated", "expected_rc"), [(True, 0), (False, 1)])
def test_cli_exit_code_follows_recommendation_status(
    tmp_path: Path,
    mini_snapshot,
    monkeypatch: pytest.MonkeyPatch,
    block_network,
    validated: bool,
    expected_rc: int,
) -> None:
    from deprisk import config
    from deprisk.agent import loop

    stub = _AgentStub(_legacy_submission(mini_snapshot) if validated else None)
    monkeypatch.setattr(loop, "make_client", lambda settings: stub)
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    reqs, snap = write_inputs(tmp_path, mini_snapshot, ["legacy", "fresh0"])
    out = tmp_path / "out"
    rc = cli.main(
        ["analyze", str(reqs), "--snapshot", str(snap), "--out", str(out), "--top-n", "1"]
    )
    assert rc == expected_rc
    results = json.loads((out / "results.json").read_text("utf-8"))
    (rec,) = results["recommendations"]
    assert rec["package"] == "legacy"
    assert rec["status"] == ("validated" if validated else "unresolved")
    assert rec["calls"][0]["name"] == "get_package_profile"
    assert results["run"]["model"] == "claude-sonnet-5-5"
    report = (out / "REPORT.md").read_text("utf-8")
    assert "1. legacy:" in report and "suitability not verified" in report

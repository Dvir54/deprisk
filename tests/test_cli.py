"""CLI entry point and exit codes."""

from __future__ import annotations

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

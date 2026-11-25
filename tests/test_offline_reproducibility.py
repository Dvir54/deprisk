"""AC2: scoring the committed snapshot offline reproduces the committed results exactly."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from deprisk.config import SIGNALS
from deprisk.data.requirements import parse_requirements
from deprisk.data.snapshot import load_snapshot
from deprisk.reporting.results_json import build_results
from deprisk.risk.analysis import analyze

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "data" / "snapshot.json.gz"
RESULTS = ROOT / "output" / "results.json"
REQUIREMENTS = ROOT / "assignment" / "requirements.txt"


def _comparable(packages: list[dict]) -> list[dict]:
    """The deterministic part of each package: rank, scores and every contribution."""
    return [
        {
            "name": p["name"],
            "rank": p["rank"],
            "final_score": p["final_score"],
            "total": p["total"],
            "contributions": {s: p["signals"][s]["contribution"] for s in SIGNALS},
        }
        for p in packages
    ]


def test_block_network_refuses_connections(block_network) -> None:
    with pytest.raises(OSError, match="blocked"):
        socket.create_connection(("127.0.0.1", 9))


def test_scores_and_ranks_match_committed_results(block_network) -> None:
    committed = json.loads(RESULTS.read_text(encoding="utf-8"))
    requirements, issues = parse_requirements(REQUIREMENTS)
    result = analyze(load_snapshot(SNAPSHOT), requirements, issues=issues)
    fresh = build_results(result, None)

    assert len(fresh["packages"]) == 40
    assert fresh["unscored"] == committed["unscored"] == {}
    assert _comparable(fresh["packages"]) == _comparable(committed["packages"])
    for key in ("snapshot_id", "T", "baseline_n", "config_hash"):
        assert fresh["run"][key] == committed["run"][key]

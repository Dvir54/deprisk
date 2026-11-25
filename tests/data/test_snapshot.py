"""Snapshot persistence and the reference time T (SPEC §9.2, D13)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from deprisk.data.models import Snapshot, SnapshotDataError
from deprisk.data.snapshot import load_snapshot, reference_time, save_snapshot

T0 = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def sample_snapshot(make_record) -> Snapshot:
    rec = make_record(
        {
            "1.0": [{}],
            "2.0": [{"packagetype": "bdist_wheel", "requires_python": ">=3.8"}],
            "0.1": [],
        },
        {
            "2.0": {
                "classifiers": ["X"],
                "requires_dist": None,
                "vulnerabilities": [{"id": "GHSA-1"}],
            }
        },
        name="alpha",
    )
    return Snapshot(
        meta={"T": T0.isoformat(), "exclusions": {"gone": "data unavailable"}},
        baseline_names=("alpha",),
        records={"alpha": rec},
    )


def test_save_load_roundtrip_identical(tmp_path: Path, make_record) -> None:
    snap = sample_snapshot(make_record)
    path = tmp_path / "snap.json.gz"
    save_snapshot(snap, path)
    assert load_snapshot(path) == snap


def test_save_is_byte_for_byte_deterministic(tmp_path: Path, make_record) -> None:
    snap = sample_snapshot(make_record)
    save_snapshot(snap, tmp_path / "a.json.gz")
    save_snapshot(snap, tmp_path / "b.json.gz")
    assert (tmp_path / "a.json.gz").read_bytes() == (tmp_path / "b.json.gz").read_bytes()


def test_missing_snapshot_is_a_hard_error(tmp_path: Path) -> None:
    with pytest.raises(SnapshotDataError):
        load_snapshot(tmp_path / "absent.json.gz")


def test_t_includes_version_endpoint_fetch_time(make_record) -> None:
    rec = make_record({"1.0": [{}]}, {"1.0": {}})
    later = T0 + timedelta(minutes=5)
    rec = rec.model_copy(update={"fetched_at": T0, "version_fetched_at": {"1.0": later}})
    assert reference_time(T0 - timedelta(hours=1), [rec]) == later


def test_t_includes_top_list_fetch_time(make_record) -> None:
    rec = make_record({"1.0": [{}]}).model_copy(update={"fetched_at": T0})
    top_list_time = T0 + timedelta(hours=2)
    assert reference_time(top_list_time, [rec]) == top_list_time


def test_t_is_latest_project_fetch_time(make_record) -> None:
    a = make_record({"1.0": [{}]}, name="a").model_copy(update={"fetched_at": T0})
    b = make_record({"1.0": [{}]}, name="b").model_copy(
        update={"fetched_at": T0 + timedelta(seconds=30)}
    )
    assert reference_time(T0 - timedelta(days=1), [a, b]) == T0 + timedelta(seconds=30)

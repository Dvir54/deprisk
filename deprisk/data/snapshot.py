"""Snapshot persistence (gzip JSON) and the reference time ``T`` (SPEC §9.2, D13).

The file is deterministic: keys sorted, compact separators, ISO-8601 UTC times, and a
fixed gzip header time, so saving the same snapshot twice gives identical bytes.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from deprisk.data.models import PackageRecord, Snapshot, SnapshotDataError


def save_snapshot(snap: Snapshot, path: Path) -> None:
    """Write the snapshot as deterministic gzip-compressed JSON."""
    payload = json.dumps(snap.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(payload.encode("utf-8"), mtime=0))


def load_snapshot(path: Path) -> Snapshot:
    """Read a snapshot; a missing or unreadable file is a hard error (never a silent fetch)."""
    if not path.is_file():
        raise SnapshotDataError(f"Snapshot not found: {path}")
    try:
        # pydantic parses the JSON itself: about twice as fast as json.loads + validate.
        return Snapshot.model_validate_json(gzip.decompress(path.read_bytes()))
    except (OSError, ValueError, ValidationError) as exc:
        raise SnapshotDataError(f"Snapshot {path} is unreadable: {exc}") from exc


def reference_time(top_list_fetched_at: datetime, records: Iterable[PackageRecord]) -> datetime:
    """``T`` = the latest fetch time over every response the snapshot is built from:
    the top list, each project response and each version-endpoint response."""
    times = [top_list_fetched_at]
    for record in records:
        times.append(record.fetched_at)
        times.extend(record.version_fetched_at.values())
    return max(times)

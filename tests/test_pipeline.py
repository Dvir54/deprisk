"""Phase orchestration (no network: httpx.MockTransport)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deprisk import pipeline
from deprisk.config import ConfigError
from deprisk.data.models import FetchError
from deprisk.data.pypi_client import top_package_names

TOP_LIST = {
    "last_update": "2026-11-01 06:41:05",
    "rows": [
        {"project": "boto3", "download_count": 300},
        {"project": "gone-pkg", "download_count": 200},
        {"project": "six", "download_count": 100},
        {"project": "tail", "download_count": 50},
    ],
}


def test_top_package_names_sorted_by_downloads_with_stable_ties() -> None:
    top = {
        "rows": [
            {"project": "b", "download_count": 5},
            {"project": "a", "download_count": 9},
            {"project": "c", "download_count": 5},
        ]
    }
    assert top_package_names(top, 3) == ["a", "b", "c"]
    with pytest.raises(FetchError):
        top_package_names(top, 4)


def test_fetch_baseline_fetches_first_n_and_reports(tmp_path: Path) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "hugovk.github.io":
            return httpx.Response(200, json=TOP_LIST)
        name = request.url.path.split("/")[2]
        requested.append(name)
        if name == "gone-pkg":
            return httpx.Response(404)
        return httpx.Response(200, json={"info": {"name": name}, "releases": {}})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    report = pipeline.fetch_baseline(limit=3, cache_dir=tmp_path, http=http)
    assert report.ok == ["boto3", "six"]
    assert report.missing == ["gone-pkg"]
    assert report.failed == {}
    assert sorted(requested) == ["boto3", "gone-pkg", "six"]  # "tail" is beyond the limit


@pytest.mark.parametrize("limit", [0, -1, 5001])
def test_fetch_baseline_rejects_bad_limit(limit: int, tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        pipeline.fetch_baseline(limit=limit, cache_dir=tmp_path)

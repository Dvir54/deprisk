"""Phase orchestration (no network: httpx.MockTransport)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from packaging.specifiers import SpecifierSet

from deprisk import config, pipeline
from deprisk.config import CONFIG_HASH, ConfigError
from deprisk.data.models import FetchError, Requirement
from deprisk.data.pypi_client import top_package_names
from deprisk.data.snapshot import load_snapshot

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


# --- build_snapshot (stub client, no network) ------------------------------------------

T_TOP = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def sdist(version: str, requires_python: str | None = None) -> dict:
    return {
        "filename": f"p-{version}.tar.gz",
        "packagetype": "sdist",
        "upload_time_iso_8601": "2024-01-01T00:00:00Z",
        "yanked": False,
        "requires_python": requires_python,
    }


def project(name: str, releases: dict[str, list[dict]], latest: str) -> dict:
    return {
        "info": {"name": name, "version": latest, "classifiers": [], "requires_dist": []},
        "last_serial": 1,
        "ownership": {"roles": []},
        "releases": releases,
        "vulnerabilities": [],
    }


VERSION_JSON = {"info": {"classifiers": [], "requires_dist": ["six"]}, "vulnerabilities": []}


class StubClient:
    """Answers like PyPIClient from in-memory data and records version-endpoint requests."""

    def __init__(self, projects: dict[str, Any], versions: dict[tuple[str, str], Any]) -> None:
        self.projects = projects
        self.versions = versions
        self.version_requests: list[tuple[str, str]] = []

    def get_top_list(self) -> tuple[dict, datetime]:
        return {"last_update": "2026-11-01 06:41:05", "rows": []}, T_TOP

    def get_project(self, name: str) -> tuple[dict, datetime] | None:
        value = self.projects.get(name)
        if isinstance(value, Exception):
            raise value
        return None if value is None else (value, T_TOP - timedelta(minutes=10))

    def get_version(self, name: str, version: str) -> tuple[dict, datetime] | None:
        self.version_requests.append((name, version))
        value = self.versions.get((name, version))
        if isinstance(value, Exception):
            raise value
        return None if value is None else (value, T_TOP + timedelta(minutes=3))


# "fallback": the latest release (2.0) excludes 3.12, so the reference version is 1.0.
FALLBACK = project("fallback", {"1.0": [sdist("1.0")], "2.0": [sdist("2.0", "<3")]}, "2.0")
HEALTHY = project("healthy", {"1.0": [sdist("1.0")], "2.0": [sdist("2.0")]}, "2.0")


def test_build_fetches_version_endpoint_when_reference_not_latest() -> None:
    client = StubClient(
        {"fallback": FALLBACK, "healthy": HEALTHY}, {("fallback", "1.0"): VERSION_JSON}
    )
    snap = pipeline.build_snapshot(client, ["fallback", "healthy"], [], include_targets=False)
    assert client.version_requests == [("fallback", "1.0")]
    assert snap.records["fallback"].version_meta["1.0"].requires_dist == ("six",)
    assert snap.meta["T"] == (T_TOP + timedelta(minutes=3)).isoformat()  # version fetch is latest


def test_build_excludes_package_when_needed_version_fetch_fails() -> None:
    client = StubClient(
        {"fallback": FALLBACK, "healthy": HEALTHY, "broken": FetchError("boom"), "gone": None},
        {("fallback", "1.0"): None},
    )
    snap = pipeline.build_snapshot(
        client, ["fallback", "healthy", "broken", "gone"], [], include_targets=False
    )
    assert set(snap.records) == {"healthy"}
    assert snap.meta["exclusions"] == {
        "broken": "data unavailable",
        "fallback": "data unavailable",
        "gone": "data unavailable",
    }
    assert snap.baseline_names == ("fallback", "healthy", "broken", "gone")


def test_build_fetches_target_reference_version_from_its_specifier() -> None:
    client = StubClient({"healthy": HEALTHY}, {("healthy", "1.0"): VERSION_JSON})
    req = Requirement(name="healthy", specifier=SpecifierSet("<2"), line="healthy<2")
    snap = pipeline.build_snapshot(client, ["healthy"], [req], include_targets=False)
    assert client.version_requests == [("healthy", "1.0")]
    assert set(snap.records["healthy"].version_meta) == {"1.0", "2.0"}


def test_build_include_targets_adds_requirement_names() -> None:
    client = StubClient(
        {"healthy": HEALTHY, "fallback": FALLBACK}, {("fallback", "1.0"): VERSION_JSON}
    )
    req = Requirement(name="fallback", specifier=SpecifierSet(""), line="fallback")
    snap = pipeline.build_snapshot(client, ["healthy"], [req], include_targets=True)
    assert snap.baseline_names == ("healthy", "fallback")
    assert set(snap.records) == {"healthy", "fallback"}
    without = pipeline.build_snapshot(client, ["healthy"], [req], include_targets=False)
    assert set(without.records) == {"healthy"}  # targets outside the baseline are not added


def test_build_keeps_unscorable_package_without_fetching() -> None:
    pre = project("pre", {"1.0a1": [sdist("1.0a1")]}, "1.0a1")
    client = StubClient({"pre": pre}, {})
    snap = pipeline.build_snapshot(client, ["pre"], [], include_targets=False)
    assert "pre" in snap.records  # scored as unscorable (with its reason) in Phase B
    assert client.version_requests == []


def test_build_meta_records_definition_and_sources() -> None:
    client = StubClient({"healthy": HEALTHY}, {})
    snap = pipeline.build_snapshot(
        client, ["healthy"], [], include_targets=False, definition="sample of 1"
    )
    meta = snap.meta
    assert meta["T"] == T_TOP.isoformat()
    assert meta["top_list"] == {
        "last_update": "2026-11-01 06:41:05",
        "fetched_at": T_TOP.isoformat(),
    }
    assert meta["baseline"]["definition"] == "sample of 1"
    assert meta["baseline"]["include_targets"] is False
    assert meta["config_hash"] == CONFIG_HASH
    assert meta["env"]["marker_env"]["sys_platform"] == "linux"
    assert isinstance(meta["id"], str) and meta["id"]


# --- run_analysis and create_snapshot ---------------------------------------------------


def test_pipeline_twice_identical_outputs(tmp_path: Path, mini_snapshot) -> None:
    from deprisk.data.snapshot import save_snapshot

    snap = tmp_path / "snap.json.gz"
    save_snapshot(mini_snapshot, snap)
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("legacy\nfresh2\nfallback\nbeta\n", encoding="utf-8")
    for out in ("a", "b"):
        rc = pipeline.run_analysis(reqs, snap, tmp_path / out, use_llm=False, top_n=10)
        assert rc == 1  # beta is unscored
    for name in ("results.json", "REPORT.md"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def project_handler(top_list: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "hugovk.github.io":
            return httpx.Response(200, json=top_list)
        name = request.url.path.split("/")[2]
        return httpx.Response(200, json=project(name, {"1.0": [sdist("1.0")]}, "1.0"))

    return httpx.MockTransport(handler)


SIX_TOP = {
    "last_update": "2026-11-01 06:41:05",
    "rows": [{"project": f"p{i}", "download_count": 100 - i} for i in range(6)],
}


def test_create_snapshot_sample_is_evenly_spaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "TOP_N", 6)
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("extra-target\n", encoding="utf-8")
    out = tmp_path / "snap.json.gz"
    snap = pipeline.create_snapshot(
        out,
        sample=3,
        requirements_path=reqs,
        include_targets=True,
        cache_dir=tmp_path / "cache",
        http=httpx.Client(transport=project_handler(SIX_TOP)),
    )
    assert snap.baseline_names == ("p0", "p2", "p4", "extra-target")
    assert snap.meta["baseline"]["definition"] == (
        "3 evenly spaced ranks of the top 6 PyPI projects by downloads, "
        "plus the requirement targets"
    )
    assert load_snapshot(out) == snap


def test_create_snapshot_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "TOP_N", 6)
    snap = pipeline.create_snapshot(
        tmp_path / "s.json.gz",
        limit=2,
        requirements_path=None,
        cache_dir=tmp_path / "cache",
        http=httpx.Client(transport=project_handler(SIX_TOP)),
    )
    assert snap.baseline_names == ("p0", "p1")
    assert snap.meta["baseline"]["definition"].startswith("top 2 PyPI projects by downloads")


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"sample": 7}, {"limit": 2, "sample": 2}])
def test_create_snapshot_rejects_bad_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kwargs, block_network
) -> None:
    monkeypatch.setattr(config, "TOP_N", 6)
    with pytest.raises(ConfigError):
        pipeline.create_snapshot(tmp_path / "s.json.gz", cache_dir=tmp_path, **kwargs)

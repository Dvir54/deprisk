"""PyPI client: retries, 404 handling, atomic gzip cache (httpx.MockTransport, no network)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from deprisk.config import HTTP_MAX_RETRIES, USER_AGENT
from deprisk.data.models import FetchError
from deprisk.data.pypi_client import PyPIClient

Handler = Callable[[httpx.Request], httpx.Response]


def make_client(tmp_path: Path, handler: Handler) -> tuple[PyPIClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.Client(transport=httpx.MockTransport(recording))
    return PyPIClient(tmp_path / "cache", client=http, sleep=lambda _: None), seen


def project_json(name: str) -> dict:
    return {"info": {"name": name, "version": "1.0"}, "last_serial": 7, "releases": {}}


def test_retries_then_succeeds_on_503(tmp_path: Path) -> None:
    responses = iter([httpx.Response(503), httpx.Response(503)])

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses, httpx.Response(200, json=project_json("flask")))

    client, seen = make_client(tmp_path, handler)
    body, fetched_at = client.get_project("flask")
    assert body["info"]["name"] == "flask"
    assert fetched_at.tzinfo is not None
    assert len(seen) == 3


def test_404_returns_none_without_retry(tmp_path: Path) -> None:
    client, seen = make_client(tmp_path, lambda r: httpx.Response(404))
    assert client.get_project("no-such-package") is None
    assert len(seen) == 1
    assert client.get_project("no-such-package") is None  # cached: no second request
    assert len(seen) == 1


def test_gives_up_after_max_retries_and_reports_failure(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/pypi/broken/"):
            return httpx.Response(500)
        return httpx.Response(200, json=project_json("ok"))

    client, seen = make_client(tmp_path, handler)
    with pytest.raises(FetchError):
        client.get_project("broken")
    assert len(seen) == HTTP_MAX_RETRIES + 1

    report = client.fetch_projects(["ok", "broken"])
    assert report.ok == ["ok"]
    assert report.missing == []
    assert list(report.failed) == ["broken"]
    assert not (tmp_path / "cache" / "projects" / "broken.json.gz").exists()


def test_timeout_is_retried(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json=project_json("six"))

    client, _ = make_client(tmp_path, handler)
    assert client.get_project("six") is not None
    assert calls["n"] == 2


def test_cache_hit_makes_no_request_and_keeps_fetched_at(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path, lambda r: httpx.Response(200, json=project_json("six")))
    first_body, first_time = client.get_project("six")

    fresh, fresh_seen = make_client(tmp_path, lambda r: httpx.Response(500))
    body, fetched_at = fresh.get_project("six")
    assert fresh_seen == []
    assert (body, fetched_at) == (first_body, first_time)


def test_refresh_ignores_cache(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path, lambda r: httpx.Response(200, json=project_json("six")))
    client.get_project("six")
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    refreshing = PyPIClient(tmp_path / "cache", client=http, refresh=True, sleep=lambda _: None)
    assert refreshing.get_project("six") is None


def test_version_endpoint_and_names_are_normalised(tmp_path: Path) -> None:
    client, seen = make_client(tmp_path, lambda r: httpx.Response(200, json=project_json("x")))
    client.get_version("Foo_Bar", "2.0.0")
    assert seen[0].url.path == "/pypi/Foo_Bar/2.0.0/json"
    assert (tmp_path / "cache" / "versions" / "foo-bar" / "2.0.0.json.gz").exists()


def test_user_agent_header_sent(tmp_path: Path) -> None:
    client, seen = make_client(tmp_path, lambda r: httpx.Response(200, json=project_json("six")))
    client.get_project("six")
    assert seen[0].headers["User-Agent"] == USER_AGENT

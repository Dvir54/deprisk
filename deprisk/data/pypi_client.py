"""HTTP access to PyPI and the top-packages list, with retries and an atomic gzip cache.

Every response is cached as ``{"fetched_at": <ISO-8601 UTC>, "body": <JSON or null>}``
(``null`` = 404). A cache hit returns the original ``fetched_at``, so the snapshot's
reference time ``T`` is a property of the cached data, not of when extraction ran.
Writes go to a temporary file that is then moved into place, so a reader (e.g. a
smoke snapshot built while the full download runs) never sees a partial file.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

import httpx
from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field

from deprisk import config
from deprisk.data.models import FetchError

log = logging.getLogger(__name__)

_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_RETRY_EXCEPTIONS = (httpx.TimeoutException, httpx.TransportError)

Fetched = tuple[Any, datetime]


class FetchReport(BaseModel):
    """Outcome of a bulk project download, in input order.

    Mutable on purpose (filled in while downloads complete), so it is not a FrozenModel.
    """

    ok: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)  # 404 on PyPI
    failed: dict[str, str] = Field(default_factory=dict)  # name -> error


class PyPIClient:
    """Fetches PyPI JSON with retry/backoff; caches every response on disk.

    ``cache_dir=None`` disables caching. ``client`` and ``sleep`` are injectable
    so tests run without network or real waiting.
    """

    def __init__(
        self,
        cache_dir: Path | None,
        client: httpx.Client | None = None,
        *,
        refresh: bool = False,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._cache_dir = cache_dir
        self._refresh = refresh
        self._sleep = sleep
        self._owns_client = client is None
        self._http = client or httpx.Client(timeout=config.HTTP_TIMEOUT_S, follow_redirects=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    # --- public API -------------------------------------------------------------
    def get_top_list(self) -> Fetched:
        """Return the top-packages list JSON and its fetch time (raises FetchError)."""
        result = self._get_cached(config.TOP_LIST_URL, self._path("top-list.json.gz"))
        if result is None:
            raise FetchError(f"Top list not found: {config.TOP_LIST_URL}")
        return result

    def get_project(self, name: str) -> Fetched | None:
        """Return ``/pypi/<name>/json`` and its fetch time, or None on 404."""
        url = config.PYPI_PROJECT_URL.format(name=name)
        return self._get_cached(url, self._path("projects", f"{canonicalize_name(name)}.json.gz"))

    def get_version(self, name: str, version: str) -> Fetched | None:
        """Return ``/pypi/<name>/<version>/json`` and its fetch time, or None on 404."""
        url = config.PYPI_VERSION_URL.format(name=name, version=version)
        path = self._path("versions", canonicalize_name(name), f"{version}.json.gz")
        return self._get_cached(url, path)

    def fetch_projects(self, names: Sequence[str]) -> FetchReport:
        """Download (or read from cache) every project concurrently; never raises."""

        def fetch(name: str) -> tuple[str, str | None]:
            try:
                return ("ok" if self.get_project(name) is not None else "missing"), None
            except FetchError as exc:
                return "failed", str(exc)

        report = FetchReport()
        with ThreadPoolExecutor(max_workers=config.HTTP_CONCURRENCY) as pool:
            outcomes = pool.map(fetch, names)  # results come back in input order
            for done, (name, (status, error)) in enumerate(zip(names, outcomes, strict=True), 1):
                if status == "ok":
                    report.ok.append(name)
                elif status == "missing":
                    report.missing.append(name)
                else:
                    report.failed[name] = error or "unknown error"
                    log.warning("Failed to fetch %s: %s", name, error)
                if done % config.FETCH_PROGRESS_EVERY == 0 or done == len(names):
                    log.info("Fetched %d/%d projects", done, len(names))
        return report

    # --- internals --------------------------------------------------------------
    def _path(self, *parts: str) -> Path | None:
        return self._cache_dir.joinpath(*parts) if self._cache_dir else None

    def _get_cached(self, url: str, path: Path | None) -> Fetched | None:
        if path is not None and not self._refresh and path.exists():
            entry = _read_entry(path)
            body, fetched_at = entry["body"], datetime.fromisoformat(entry["fetched_at"])
        else:
            body, fetched_at = self._request(url)
            if path is not None:
                _write_entry(path, {"fetched_at": fetched_at.isoformat(), "body": body})
        return None if body is None else (body, fetched_at)

    def _request(self, url: str) -> tuple[Any | None, datetime]:
        """GET with retries on 429/5xx/timeouts; 404 → (None, time); else FetchError."""
        last_error = ""
        last_retry_after: float | None = None
        for attempt in range(config.HTTP_MAX_RETRIES + 1):
            if attempt:
                self._sleep(_backoff(attempt, last_retry_after))
                last_retry_after = None
            try:
                response = self._http.get(url, headers={"User-Agent": config.USER_AGENT})
            except _RETRY_EXCEPTIONS as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue
            fetched_at = datetime.now(UTC)
            if response.status_code == 404:
                return None, fetched_at
            if response.status_code in _RETRY_STATUSES:
                last_error = f"HTTP {response.status_code}"
                last_retry_after = _retry_after(response)
                continue
            if response.status_code != 200:
                raise FetchError(f"{url}: HTTP {response.status_code}")
            try:
                return response.json(), fetched_at
            except ValueError as exc:
                raise FetchError(f"{url}: invalid JSON ({exc})") from exc
        raise FetchError(f"{url}: gave up after {config.HTTP_MAX_RETRIES} retries ({last_error})")


def top_package_names(top_list: Mapping[str, Any], n: int) -> list[str]:
    """First ``n`` project names by download count (stable order on ties).

    Raises FetchError if the list is malformed or has fewer than ``n`` rows.
    """
    try:
        rows = [(row["project"], int(row["download_count"])) for row in top_list["rows"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise FetchError(f"Malformed top-packages list: {exc!r}") from exc
    if len(rows) < n:
        raise FetchError(f"Top-packages list has {len(rows)} rows, need {n}")
    rows.sort(key=lambda row: -row[1])  # list.sort is stable: ties keep list order
    return [name for name, _ in rows[:n]]


def _backoff(attempt: int, retry_after: float | None) -> float:
    """Exponential backoff (1, 2, 4, 8 s), never shorter than the server's Retry-After."""
    delay = config.HTTP_BACKOFF_BASE_S * 2 ** (attempt - 1)
    return max(delay, retry_after or 0.0)


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After", "")
    return float(value) if value.isdigit() else None


def _read_entry(path: Path) -> dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def _write_entry(path: Path, entry: dict[str, Any]) -> None:
    """Write atomically: temp file in the same directory, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.open(raw, "wt", encoding="utf-8") as fh:
            json.dump(entry, fh)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise

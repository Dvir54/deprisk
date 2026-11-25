"""Phase orchestration and file IO: the only module that wires the subpackages together.

``deprisk.agent.loop`` (and so ``anthropic``) is imported lazily inside the
functions that need it, so ``--no-llm`` runs never load the SDK.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from deprisk import config
from deprisk.config import ConfigError, llm_settings
from deprisk.data.pypi_client import FetchReport, PyPIClient, top_package_names

if TYPE_CHECKING:
    import httpx

log = logging.getLogger(__name__)


def fetch_baseline(
    limit: int | None = None,
    *,
    refresh: bool = False,
    cache_dir: Path = config.CACHE_DIR,
    http: httpx.Client | None = None,
) -> FetchReport:
    """Phase A, step 1: cache the top list and the first ``limit`` (default TOP_N) projects.

    Resumable: cached responses are reused unless ``refresh`` is set.
    """
    n = config.TOP_N if limit is None else limit
    if not 1 <= n <= config.TOP_N:
        raise ConfigError(f"--limit must be between 1 and {config.TOP_N}, got {n}")
    with PyPIClient(cache_dir, client=http, refresh=refresh) as pypi:
        top_list, fetched_at = pypi.get_top_list()
        log.info(
            "Top list last_update %s (fetched %s); fetching %d projects",
            top_list.get("last_update"),
            fetched_at.isoformat(),
            n,
        )
        return pypi.fetch_projects(top_package_names(top_list, n))


def check_llm() -> dict[str, Any]:
    """Run the LLM connectivity check with the configured model and effort."""
    from deprisk.agent.loop import check_connectivity, make_client

    settings = llm_settings()
    return check_connectivity(make_client(settings), settings)

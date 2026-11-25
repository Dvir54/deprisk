"""Central configuration: every tunable constant of the tool lives here.

Scoring and environment settings are fixed values (they define the model and are
covered by ``CONFIG_HASH``). Only the LLM model and effort can be overridden, via
environment variables read by :func:`llm_settings`.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class ConfigError(Exception):
    """Invalid configuration or missing credentials (CLI exit code 2)."""


# --- Paths and data sources -------------------------------------------------
CACHE_DIR = Path(".cache/pypi")
SNAPSHOT_PATH = Path("data/snapshot.json.gz")
OUTPUT_DIR = Path("output")
REQUIREMENTS_PATH = Path("assignment/requirements.txt")
TOP_LIST_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
PYPI_PROJECT_URL = "https://pypi.org/pypi/{name}/json"
PYPI_VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"

# --- Baseline -----------------------------------------------------------------
TOP_N = 5000
SMOKE_SAMPLE = 300

# --- HTTP (PyPI) --------------------------------------------------------------
HTTP_CONCURRENCY = 8
HTTP_TIMEOUT_S = 30
HTTP_MAX_RETRIES = 4
HTTP_BACKOFF_BASE_S = 1.0  # retry delays 1, 2, 4, 8 s
FETCH_PROGRESS_EVERY = 250
USER_AGENT = "deprisk/0.1 (dependency-risk home assignment)"  # no personal data

# --- Signals and scoring (SPEC §8, §10) ----------------------------------------
S2_WINDOW_DAYS = 730  # "24 months"
SIGNALS: tuple[str, ...] = ("S1", "S2", "S4", "S5", "S6", "S7")
CATEGORIES: Mapping[str, tuple[str, ...]] = {
    "maintenance": ("S1", "S2"),
    "compatibility": ("S4", "S5"),
    "security": ("S6",),
    "dependencies": ("S7",),
}
# S2 (releases in the window) is the only signal where a lower value is riskier.
HIGHER_IS_RISKIER: Mapping[str, bool] = {s: s != "S2" for s in SIGNALS}
NEUTRAL_Q = 0.5  # placement used for unknown values (contribution ln 2)
ROUND_DECIMALS = 6
SCORE_DECIMALS = 2

# --- Target environment (SPEC §12.1) -------------------------------------------
PYTHON_VERSION = (3, 12)
PYTHON_FULL_VERSION = "3.12.0"
PLATFORM_ARCH = "x86_64"
# Perennial manylinux tags from glibc 2.36 down to 2.5 (approved range), newest first.
MANYLINUX_GLIBC_MINORS: tuple[int, ...] = tuple(range(36, 4, -1))
LEGACY_MANYLINUX: tuple[str, ...] = ("manylinux2014", "manylinux2010", "manylinux1")
# Every key of packaging.markers.default_environment() is set explicitly, so marker
# evaluation never falls back to a value read from the host machine. The keys that
# SPEC §12.1 does not name (implementation_version, platform_release,
# platform_version) get fixed values.
MARKER_ENV: Mapping[str, str] = {
    "implementation_name": "cpython",
    "implementation_version": PYTHON_FULL_VERSION,
    "os_name": "posix",
    "platform_machine": PLATFORM_ARCH,
    "platform_python_implementation": "CPython",
    "platform_release": "",
    "platform_system": "Linux",
    "platform_version": "",
    "python_full_version": PYTHON_FULL_VERSION,
    "python_version": "3.12",
    "sys_platform": "linux",
}

# --- Agent ----------------------------------------------------------------------
AGENT_TOP_N = 10
MAX_TOOL_CALLS = 8  # per attempt
MAX_RETRIES = 2  # validator-driven retries after the first attempt
MAX_LLM_REQUESTS_PER_PACKAGE = (MAX_RETRIES + 1) * (MAX_TOOL_CALLS + 2)
HISTORY_LIMIT = 40
ADVISORY_SUMMARY_CHARS = 200

# --- LLM ------------------------------------------------------------------------
LLM_MODEL_ENV = "DEPRISK_LLM_MODEL"
LLM_EFFORT_ENV = "DEPRISK_LLM_EFFORT"
DEFAULT_LLM_MODEL = "claude-sonnet-5-5"
DEFAULT_LLM_EFFORT = "medium"
LLM_EFFORT_LEVELS: tuple[str, ...] = ("low", "medium", "high", "xhigh", "max")
LLM_MAX_TOKENS = 16000
LLM_TIMEOUT_S = 120
LLM_SDK_MAX_RETRIES = 2


class LLMSettings(BaseModel):
    """Model and request settings for every Claude call.

    Subclasses ``BaseModel`` directly: config imports no deprisk module, so it cannot
    use ``data.models.FrozenModel``; same settings (immutable, unknown fields rejected).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str
    effort: str
    max_tokens: int = LLM_MAX_TOKENS
    timeout_s: float = LLM_TIMEOUT_S
    sdk_max_retries: int = LLM_SDK_MAX_RETRIES


def llm_settings(env: Mapping[str, str] | None = None) -> LLMSettings:
    """Read the LLM model and effort, applying environment overrides.

    Raises ConfigError for an unknown effort level or an empty model name.
    """
    env = os.environ if env is None else env
    model = env.get(LLM_MODEL_ENV, DEFAULT_LLM_MODEL).strip()
    effort = env.get(LLM_EFFORT_ENV, DEFAULT_LLM_EFFORT).strip().lower()
    if not model:
        raise ConfigError(f"{LLM_MODEL_ENV} is set but empty")
    if effort not in LLM_EFFORT_LEVELS:
        allowed = ", ".join(LLM_EFFORT_LEVELS)
        raise ConfigError(f"{LLM_EFFORT_ENV}={effort!r} is not one of: {allowed}")
    return LLMSettings(model=model, effort=effort)


def _config_hash() -> str:
    """Hash of every setting that can change a deterministic score (not the LLM ones)."""
    scoring = {
        "TOP_N": TOP_N,
        "S2_WINDOW_DAYS": S2_WINDOW_DAYS,
        "SIGNALS": SIGNALS,
        "CATEGORIES": dict(CATEGORIES),
        "HIGHER_IS_RISKIER": dict(HIGHER_IS_RISKIER),
        "NEUTRAL_Q": NEUTRAL_Q,
        "ROUND_DECIMALS": ROUND_DECIMALS,
        "SCORE_DECIMALS": SCORE_DECIMALS,
        "PYTHON_VERSION": PYTHON_VERSION,
        "PYTHON_FULL_VERSION": PYTHON_FULL_VERSION,
        "PLATFORM_ARCH": PLATFORM_ARCH,
        "MANYLINUX_GLIBC_MINORS": MANYLINUX_GLIBC_MINORS,
        "LEGACY_MANYLINUX": LEGACY_MANYLINUX,
        "MARKER_ENV": dict(MARKER_ENV),
    }
    payload = json.dumps(scoring, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


CONFIG_HASH = _config_hash()

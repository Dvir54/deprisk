"""LLM settings from the environment, and host-independent configuration."""

from __future__ import annotations

import pytest
from packaging.markers import default_environment

from deprisk import config


def test_llm_defaults_sonnet_medium() -> None:
    settings = config.llm_settings({})
    assert settings.model == "claude-sonnet-5-5"
    assert settings.effort == "medium"


def test_llm_env_overrides() -> None:
    settings = config.llm_settings(
        {"DEPRISK_LLM_MODEL": "claude-opus-5-5", "DEPRISK_LLM_EFFORT": "HIGH"}
    )
    assert (settings.model, settings.effort) == ("claude-opus-5-5", "high")


@pytest.mark.parametrize("env", [{"DEPRISK_LLM_EFFORT": "extreme"}, {"DEPRISK_LLM_MODEL": "  "}])
def test_invalid_effort_rejected(env: dict[str, str]) -> None:
    with pytest.raises(config.ConfigError):
        config.llm_settings(env)


def test_marker_env_covers_every_host_key() -> None:
    """No marker variable may fall back to a value read from the host machine."""
    assert set(default_environment()) <= set(config.MARKER_ENV)


def test_request_cap_matches_formula() -> None:
    assert config.MAX_LLM_REQUESTS_PER_PACKAGE == 30

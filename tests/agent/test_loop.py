"""Agent loop module: connectivity check and request shape (fake client, no network)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from deprisk.agent import loop
from deprisk.config import ConfigError, LLMSettings

SETTINGS = LLMSettings(model="claude-sonnet-5-5", effort="medium")

FULL_CAPABILITIES = {
    "thinking": {"supported": True, "types": {"adaptive": {"supported": True}}},
    "effort": {"supported": True, "medium": {"supported": True}},
    "structured_outputs": {"supported": True},
}


class FakeClient:
    """Records calls; returns SDK-shaped objects."""

    def __init__(self, capabilities: dict[str, Any]) -> None:
        self.requests: list[dict[str, Any]] = []
        info = SimpleNamespace(
            id="claude-sonnet-5-5",
            display_name="Claude Sonnet 5.5",
            max_input_tokens=1_000_000,
            capabilities=capabilities,
        )
        self.models = SimpleNamespace(retrieve=lambda model_id: info)
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs: Any) -> SimpleNamespace:
        self.requests.append(kwargs)
        return SimpleNamespace(
            model="claude-sonnet-5-5",
            stop_reason="end_turn",
            content=[
                SimpleNamespace(type="thinking", thinking=""),
                SimpleNamespace(type="text", text="OK"),
            ],
            usage=SimpleNamespace(input_tokens=42, output_tokens=7),
        )


def test_check_connectivity_reports_model_and_latency() -> None:
    client = FakeClient(FULL_CAPABILITIES)
    result = loop.check_connectivity(client, SETTINGS)
    assert result["model"] == "claude-sonnet-5-5"
    assert result["stop_reason"] == "end_turn"
    assert result["text"] == "OK"  # text read by block type, thinking block skipped
    assert result["latency_s"] >= 0
    assert (result["input_tokens"], result["output_tokens"]) == (42, 7)


def test_check_uses_production_request_shape() -> None:
    client = FakeClient(FULL_CAPABILITIES)
    loop.check_connectivity(client, SETTINGS)
    (request,) = client.requests
    assert request["output_config"] == {"effort": "medium"}
    assert request["tools"][0]["strict"] is True
    for forbidden in ("thinking", "tool_choice", "temperature", "top_p", "top_k"):
        assert forbidden not in request


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (("thinking", "types", "adaptive"), "adaptive thinking"),
        (("effort", "medium"), "effort 'medium'"),
        (("structured_outputs",), "structured outputs"),
    ],
)
def test_check_connectivity_rejects_missing_capability(
    path: tuple[str, ...], expected: str
) -> None:
    caps: dict[str, Any] = {k: dict(v) for k, v in FULL_CAPABILITIES.items()}
    node = caps
    for key in path[:-1]:
        node[key] = dict(node[key])
        node = node[key]
    node[path[-1]] = {"supported": False}
    client = FakeClient(caps)
    with pytest.raises(ConfigError, match=expected):
        loop.check_connectivity(client, SETTINGS)
    assert client.requests == []  # no message request when a capability is missing


# The capability tree the live Models API returned for claude-sonnet-5-5 (2026-11-25).
LIVE_SONNET_55_CAPABILITIES = {
    "batch": {"supported": True},
    "citations": {"supported": True},
    "code_execution": {"supported": True},
    "context_management": {
        "clear_thinking_20251015": {"supported": True},
        "clear_tool_uses_20250919": {"supported": True},
        "compact_20260112": {"supported": True},
        "supported": True,
    },
    "effort": {
        "high": {"supported": True},
        "low": {"supported": True},
        "max": {"supported": True},
        "medium": {"supported": True},
        "supported": True,
        "xhigh": {"supported": True},
    },
    "image_input": {"supported": True},
    "pdf_input": {"supported": True},
    "server_tools": {
        "code_execution": {"supported": True},
        "supported": True,
        "web_search": {"supported": True},
    },
    "structured_outputs": {"supported": True},
    "thinking": {
        "supported": True,
        "types": {
            "adaptive": {"supported": True},
            "between_tools": {"supported": True},
            "disabled": {"supported": False},
            "enabled": {"supported": False},
        },
    },
}


def test_check_connectivity_accepts_sdk_capabilities_object() -> None:
    """The real SDK returns a typed ModelCapabilities object, not a dict (found by the
    first live check-llm run): it must be read the same way."""
    from anthropic.types.model_capabilities import ModelCapabilities

    caps = ModelCapabilities.model_validate(LIVE_SONNET_55_CAPABILITIES)
    assert loop.missing_capabilities(caps, "medium") == []
    result = loop.check_connectivity(FakeClient(caps), SETTINGS)
    assert result["stop_reason"] == "end_turn"


def test_sdk_capabilities_object_still_detects_a_missing_level() -> None:
    from anthropic.types.model_capabilities import ModelCapabilities

    tree = {**LIVE_SONNET_55_CAPABILITIES, "structured_outputs": {"supported": False}}
    caps = ModelCapabilities.model_validate(tree)
    assert loop.missing_capabilities(caps, "medium") == ["structured outputs (strict tools)"]

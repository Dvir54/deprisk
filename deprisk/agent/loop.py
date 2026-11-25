"""Claude client, the shared request shape, and the connectivity check.

This is the only module that imports ``anthropic``. The per-package tool-use loop
is added in M7 and reuses :func:`request_kwargs` so every call has one shape.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any

import anthropic

from deprisk.config import ConfigError, LLMSettings

log = logging.getLogger(__name__)

# A trivial strict tool: proves the model accepts strict tool definitions with
# tool_choice "auto" (the shape the agent uses for submit_recommendation).
_PING_TOOL: dict[str, Any] = {
    "name": "ping",
    "description": "Connectivity check. Do not call this tool.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
}
_CHECK_MAX_TOKENS = 1024


def make_client(settings: LLMSettings) -> anthropic.Anthropic:
    """Create the SDK client; raise ConfigError if no credential source resolves.

    The SDK resolves ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, then credential
    profiles; a broken profile raises CredentialsError while the client is built.
    """
    try:
        client = anthropic.Anthropic(
            timeout=settings.timeout_s, max_retries=settings.sdk_max_retries
        )
    except anthropic.CredentialsError as exc:
        raise ConfigError(f"Anthropic credentials could not be loaded: {exc}") from exc
    if client.api_key is None and client.auth_token is None and client.credentials is None:
        raise ConfigError(
            "No Anthropic credentials found. Set ANTHROPIC_API_KEY "
            "(or use --no-llm to skip the agent)."
        )
    return client


def request_kwargs(
    settings: LLMSettings,
    *,
    system: str,
    messages: Sequence[Mapping[str, Any]],
    tools: Sequence[Mapping[str, Any]],
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Build the arguments of every ``messages.create`` call.

    No ``thinking`` (adaptive is the default and cannot be disabled), no sampling
    parameters (rejected), and no ``tool_choice`` (only ``auto`` is accepted).
    """
    return {
        "model": settings.model,
        "max_tokens": max_tokens or settings.max_tokens,
        "output_config": {"effort": settings.effort},
        "system": system,
        "messages": list(messages),
        "tools": list(tools),
    }


def _supported(capabilities: Mapping[str, Any] | None, *path: str) -> bool:
    """Return the ``supported`` leaf at ``path`` in the Models API capability tree."""
    node: Any = capabilities or {}
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return False
        node = node[key]
    return isinstance(node, Mapping) and node.get("supported") is True


def missing_capabilities(capabilities: Mapping[str, Any] | None, effort: str) -> list[str]:
    """List the capabilities the agent needs that the model does not report."""
    required = {
        "adaptive thinking": ("thinking", "types", "adaptive"),
        f"effort '{effort}'": ("effort", effort),
        "structured outputs (strict tools)": ("structured_outputs",),
    }
    return [name for name, path in required.items() if not _supported(capabilities, *path)]


def check_connectivity(client: Any, settings: LLMSettings) -> dict[str, Any]:
    """Verify model access, capabilities, and one request in the production shape.

    Raises ConfigError with a readable message on any failure.
    """
    try:
        info = client.models.retrieve(settings.model)
        missing = missing_capabilities(info.capabilities, settings.effort)
        if missing:
            raise ConfigError(f"Model {settings.model} lacks: {', '.join(missing)}")
        log.info(
            "Model %s (%s), context %s tokens", info.id, info.display_name, info.max_input_tokens
        )

        started = time.monotonic()
        response = client.messages.create(
            **request_kwargs(
                settings,
                system="You are a connectivity check.",
                messages=[{"role": "user", "content": "Reply with OK."}],
                tools=[_PING_TOOL],
                max_tokens=_CHECK_MAX_TOKENS,
            )
        )
        latency = time.monotonic() - started
    except anthropic.AuthenticationError as exc:
        raise ConfigError(f"Authentication failed: {exc.message}") from exc
    except anthropic.PermissionDeniedError as exc:
        raise ConfigError(f"No access to {settings.model}: {exc.message}") from exc
    except anthropic.NotFoundError as exc:
        raise ConfigError(f"Model {settings.model} not found: {exc.message}") from exc
    except anthropic.BadRequestError as exc:
        raise ConfigError(f"Request shape rejected by {settings.model}: {exc.message}") from exc
    except anthropic.APIError as exc:
        raise ConfigError(f"LLM check failed: {exc}") from exc

    text = "".join(b.text for b in response.content if b.type == "text").strip()
    result = {
        "model": response.model,
        "display_name": info.display_name,
        "max_input_tokens": info.max_input_tokens,
        "effort": settings.effort,
        "stop_reason": response.stop_reason,
        "latency_s": round(latency, 2),
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "text": text,
    }
    if response.stop_reason != "end_turn":
        log.warning("Unexpected stop_reason %s in connectivity check", response.stop_reason)
    log.info("LLM check: %s", result)
    return result

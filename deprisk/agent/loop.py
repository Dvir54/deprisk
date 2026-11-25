"""Claude client, the shared request shape, the connectivity check, and the agent loop.

This is the only module that imports ``anthropic``. Every request goes through
:func:`request_kwargs`, so the connectivity check sends the production shape.

The loop (SPEC §13, §15, D11) is a plain manual tool-use loop: the conversation is
append-only (assistant content is sent back unchanged, thinking blocks included), tools
run through ``AgentTools.call``, and each ``submit_recommendation`` is checked by the pure
validator after its evidence is collected. Three caps bound it: tool calls per attempt,
attempts per package, and LLM requests per package (the termination guarantee).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any

import anthropic

from deprisk import config
from deprisk.agent.models import Recommendation, ToolCall
from deprisk.agent.prompts import SUBMIT_NAME, SUBMIT_TOOL, SYSTEM_PROMPT
from deprisk.agent.tools import TOOL_SCHEMAS, AgentTools
from deprisk.agent.validator import top_signals, validate
from deprisk.config import ConfigError, LLMSettings
from deprisk.risk.models import PackageScore

log = logging.getLogger(__name__)

_USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)

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
    Top-level ``cache_control`` caches the growing prefix (tools, system, earlier turns),
    so each agent request re-reads its history at the cache-read price.
    """
    return {
        "model": settings.model,
        "max_tokens": max_tokens or settings.max_tokens,
        "output_config": {"effort": settings.effort},
        "cache_control": {"type": "ephemeral"},
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


def missing_capabilities(capabilities: Any, effort: str) -> list[str]:
    """List the capabilities the agent needs that the model does not report.

    ``capabilities`` is the Models API tree: the SDK returns a typed object
    (``ModelCapabilities``), which is converted to a plain dict before reading.
    """
    if capabilities is not None and not isinstance(capabilities, Mapping):
        capabilities = capabilities.to_dict()
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


# --- per-package recommendation loop (M7) -----------------------------------------------


def _user_message(package: str, tools: AgentTools, profile: ToolCall) -> str:
    """The first user turn: the deterministic profile, already logged as a citable call."""
    req = tools.requirements.get(package)
    flags = [f["code"] for f in profile.output.get("flags", [])]
    return (
        f"Package: {package}\n"
        f"Requirement line: {req.line if req is not None else package}\n"
        f"Top-2 signals: {', '.join(top_signals(profile.output)) or 'none'}. "
        f"Flags: {', '.join(flags) or 'none'}.\n"
        f"Its deterministic profile is logged as tool call {profile.id} "
        f'(get_package_profile); cite it with call_id "{profile.id}".\n'
        f"```json\n{json.dumps(profile.output, sort_keys=True, default=str)}\n```\n"
        f"Investigate with the tools as needed, then call {SUBMIT_NAME}."
    )


def _result(tool_use_id: str, content: str, is_error: bool = False) -> dict[str, Any]:
    block: dict[str, Any] = {"type": "tool_result", "tool_use_id": tool_use_id, "content": content}
    if is_error:
        block["is_error"] = True
    return block


def _stop_text(response: Any) -> str:
    """Why a response that did not ask for tools ends the attempt."""
    reason = response.stop_reason
    if reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details is not None else None
        return f"stop_reason refusal (category {category})"
    if reason == "max_tokens":
        return "stop_reason max_tokens (the response was cut off)"
    return f"stop_reason {reason} without a call to {SUBMIT_NAME}"


def recommend(
    package: str, tools: AgentTools, client: Any, settings: LLMSettings
) -> Recommendation:
    """Run the agent for one package until a submission validates or a cap is reached.

    A failed attempt is a rejected submission, a refusal, a ``max_tokens`` stop, or a
    turn that ends without a submission; after ``MAX_RETRIES`` retries the package is
    ``unresolved``. Authentication or model-access errors abort the run (ConfigError);
    any other API error makes this package ``unresolved``.
    """
    profile = tools.call(package, "get_package_profile", {})
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": _user_message(package, tools, profile)}
    ]
    tool_defs = [*TOOL_SCHEMAS, SUBMIT_TOOL]
    max_attempts = config.MAX_RETRIES + 1
    errors: list[str] = []
    usage = dict.fromkeys(_USAGE_FIELDS, 0)
    attempt, used, requests = 1, 0, 0
    model: str | None = None
    output: dict[str, Any] | None = None

    while True:
        if requests >= config.MAX_LLM_REQUESTS_PER_PACKAGE:
            errors.append(f"request limit reached ({config.MAX_LLM_REQUESTS_PER_PACKAGE})")
            break
        try:
            response = client.messages.create(
                **request_kwargs(settings, system=SYSTEM_PROMPT, messages=messages, tools=tool_defs)
            )
        except (
            anthropic.AuthenticationError,
            anthropic.PermissionDeniedError,
            anthropic.NotFoundError,
        ) as exc:
            raise ConfigError(f"Authentication or model access failed: {exc.message}") from exc
        except anthropic.APIError as exc:
            errors.append(f"API error {type(exc).__name__}: {exc}")
            log.error("%s: %s", package, errors[-1])
            break
        requests += 1
        model = response.model
        for key in _USAGE_FIELDS:
            usage[key] += getattr(response.usage, key, None) or 0
        log.info(
            "%s: request %d, attempt %d, stop_reason %s",
            package,
            requests,
            attempt,
            response.stop_reason,
        )
        if response.content:  # sent back unchanged; an empty turn is not sent
            messages.append({"role": "assistant", "content": response.content})
        uses = [b for b in response.content if b.type == "tool_use"]

        if response.stop_reason != "tool_use":
            reason = _stop_text(response)
            errors.append(f"attempt {attempt}: {reason}")
            if attempt >= max_attempts:
                break
            attempt, used = attempt + 1, 0
            results = [_result(u.id, f"not run: {reason}", is_error=True) for u in uses]
            note = f"Attempt failed ({reason}). Investigate if needed, then call {SUBMIT_NAME}."
            messages.append({"role": "user", "content": [*results, {"type": "text", "text": note}]})
            continue

        results: list[dict[str, Any]] = []
        submitted = None
        for use in uses:
            if use.name == SUBMIT_NAME:
                if submitted is None:
                    submitted = use
                else:
                    results.append(_result(use.id, "only one submission per turn", True))
            elif used >= config.MAX_TOOL_CALLS:
                results.append(_result(use.id, f"tool budget exhausted; call {SUBMIT_NAME}", True))
            else:
                used += 1
                call = tools.call(package, use.name, use.input)
                content = json.dumps({"call_id": call.id, "output": call.output}, default=str)
                results.append(_result(use.id, content, "error" in call.output))

        if submitted is not None:
            rec = dict(submitted.input)
            problems = validate(rec, tools.collect_validation_evidence(package, rec))
            if not problems:
                output = rec
                break
            errors.extend(f"attempt {attempt}: {p}" for p in problems)
            log.info("%s: attempt %d rejected: %s", package, attempt, "; ".join(problems))
            if attempt >= max_attempts:
                break
            attempt, used = attempt + 1, 0
            text = "Rejected by the validator:\n- " + "\n- ".join(problems)
            text += f"\nAttempt {attempt} of {max_attempts}: fix these and submit again."
            results.append(_result(submitted.id, text, is_error=True))
        messages.append({"role": "user", "content": results})

    status = "validated" if output is not None else "unresolved"
    log.info("%s: %s after %d request(s), %d attempt(s)", package, status, requests, attempt)
    return Recommendation(
        package=package,
        status=status,
        output=output,
        attempts=attempt,
        llm_requests=requests,
        errors=tuple(errors),
        calls=tuple(c for c in tools.log if c.package == package),
        model=model,
        usage=usage,
    )


def run_agent(
    top: Sequence[PackageScore], tools: AgentTools, client: Any, settings: LLMSettings
) -> list[Recommendation]:
    """One recommendation per package, in rank order (sequential)."""
    return [recommend(score.name, tools, client, settings) for score in top]

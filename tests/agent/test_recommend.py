"""The per-package recommendation loop (M7): scripted SDK-shaped client, no network."""

from __future__ import annotations

import json
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest
from anthropic.types import Message
from packaging.specifiers import SpecifierSet

from deprisk import config
from deprisk.agent import loop
from deprisk.agent.prompts import SUBMIT_SCHEMA, SUBMIT_TOOL, SYSTEM_PROMPT
from deprisk.agent.tools import TOOL_SCHEMAS, AgentTools
from deprisk.config import ConfigError, LLMSettings
from deprisk.data.models import Requirement
from deprisk.reporting.results_json import package_entry
from deprisk.risk.analysis import analyze
from deprisk.risk.baseline import build_baseline

SETTINGS = LLMSettings(model="claude-sonnet-5-5", effort="medium")
THINK = {"type": "thinking", "thinking": "", "signature": "sig"}


def message(stop_reason: str, *blocks: dict[str, Any], **extra: Any) -> Message:
    """A real SDK ``Message`` (not a dict), as the live API client returns."""
    return Message.model_validate(
        {
            "id": "msg_x",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-5",
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "content": list(blocks),
            "usage": {"input_tokens": 100, "output_tokens": 10, "cache_read_input_tokens": 50},
            **extra,
        }
    )


_ids = iter(range(100_000))


def use(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"type": "tool_use", "id": f"toolu_{next(_ids)}", "name": name, "input": args}


Step = Message | Exception


class ScriptedClient:
    """Plays a fixed script of responses (or a function of the request); records requests."""

    def __init__(self, script: list[Step] | Callable[[dict[str, Any]], Message]) -> None:
        self.script = script
        self.requests: list[dict[str, Any]] = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs: Any) -> Message:
        self.requests.append(kwargs)
        if callable(self.script):
            return self.script(kwargs)
        step = self.script[len(self.requests) - 1]
        if isinstance(step, Exception):
            raise step
        return step


REQS = {
    "legacy": Requirement(name="legacy", specifier=SpecifierSet(""), line="legacy"),
    "fresh0": Requirement(name="fresh0", specifier=SpecifierSet(""), line="fresh0"),
}


@pytest.fixture
def tools(mini_snapshot, fixed_t) -> AgentTools:
    result = analyze(mini_snapshot, list(REQS.values()))
    profiles = {s.name: package_entry(i, s) for i, s in enumerate(result.ranked, 1)}

    def no_live(name: str, version: str | None) -> None:
        raise AssertionError(f"unexpected live fetch {name} {version}")

    return AgentTools(
        snapshot=mini_snapshot,
        baseline=build_baseline(mini_snapshot, fixed_t),
        profiles=profiles,
        requirements=REQS,
        fetch_live=no_live,
    )


def submission(tools: AgentTools, **overrides: Any) -> dict[str, Any]:
    """A valid stdlib replacement for ``legacy`` citing its sdist_only flag (call_1 = profile)."""
    codes = [f["code"] for f in tools.profiles["legacy"]["flags"]]
    field = f"flags[{codes.index('sdist_only')}].code"
    rec = {
        "action": "replace",
        "target": "enum",
        "replacement_type": "stdlib",
        "finding": "sdist_only",
        "rationale": "Only an sdist is published.",
        "evidence": [{"call_id": "call_1", "field": field, "value": "sdist_only"}],
        "suitability_assumptions": ["The service only uses the enum API."],
        "uncertainties": [],
        "confidence": "medium",
    }
    return {**rec, **overrides}


def submit(rec: dict[str, Any]) -> Message:
    return message("tool_use", THINK, use("submit_recommendation", rec))


def tool_results(request: dict[str, Any]) -> list[dict[str, Any]]:
    last = request["messages"][-1]
    assert last["role"] == "user"
    return [b for b in last["content"] if b["type"] == "tool_result"]


def test_submit_schema_strict_and_closed() -> None:
    assert SUBMIT_TOOL["strict"] is True and SUBMIT_TOOL["name"] == "submit_recommendation"
    assert SUBMIT_TOOL["input_schema"] is SUBMIT_SCHEMA
    assert SUBMIT_SCHEMA["additionalProperties"] is False
    assert set(SUBMIT_SCHEMA["required"]) == set(SUBMIT_SCHEMA["properties"])
    item = SUBMIT_SCHEMA["properties"]["evidence"]["items"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) == set(item["properties"])
    assert "untrusted" in SYSTEM_PROMPT


def test_happy_path_validated(tools: AgentTools) -> None:
    text = {"type": "text", "text": "Looking."}
    first = message("tool_use", THINK, text, use("get_release_history", {}))
    rec = submission(tools)
    client = ScriptedClient([first, submit(rec)])

    out = loop.recommend("legacy", tools, client, SETTINGS)

    assert out.status == "validated" and out.output == rec and out.errors == ()
    assert (out.attempts, out.llm_requests, out.model) == (1, 2, "claude-sonnet-5-5")
    assert out.usage["input_tokens"] == 200 and out.usage["cache_read_input_tokens"] == 100
    assert [c.name for c in out.calls] == ["get_package_profile", "get_release_history"]
    request = client.requests[0]
    assert request["system"] == SYSTEM_PROMPT and request["output_config"] == {"effort": "medium"}
    names = [t["name"] for t in request["tools"]]
    assert names == [*(t["name"] for t in TOOL_SCHEMAS), "submit_recommendation"]
    assert "call_1" in request["messages"][0]["content"]  # the profile is a citable logged call
    (result,) = tool_results(client.requests[1])
    assert json.loads(result["content"])["call_id"] == "call_2"
    assert not result.get("is_error")


def test_assistant_content_appended_unchanged(tools: AgentTools) -> None:
    first = message("tool_use", THINK, use("get_release_history", {}))
    client = ScriptedClient([first, submit(submission(tools))])
    loop.recommend("legacy", tools, client, SETTINGS)
    history = client.requests[1]["messages"]
    assert [m["role"] for m in history] == ["user", "assistant", "user"]
    assert history[1]["content"] is first.content  # same blocks, thinking block first
    assert client.requests[0]["messages"][0] is history[0]  # earlier turns never rebuilt


def test_retry_after_validator_error_then_valid(tools: AgentTools) -> None:
    bad = submission(tools, suitability_assumptions=[])
    client = ScriptedClient([submit(bad), submit(submission(tools))])
    out = loop.recommend("legacy", tools, client, SETTINGS)
    assert out.status == "validated" and out.attempts == 2
    assert any("suitability_assumptions" in e for e in out.errors)
    (result,) = tool_results(client.requests[1])
    assert result["is_error"] is True and "suitability_assumptions" in result["content"]


def test_unresolved_after_three_failed_attempts(tools: AgentTools) -> None:
    bad = submission(tools, target="notamodule")
    client = ScriptedClient(lambda _: submit(bad))
    out = loop.recommend("legacy", tools, client, SETTINGS)
    assert out.status == "unresolved" and out.output is None
    assert out.attempts == config.MAX_RETRIES + 1 == 3
    assert len(client.requests) == out.llm_requests == 3  # no request after the last failure
    assert sum("stdlib" in e for e in out.errors) == 3


def test_tool_budget_enforced_per_attempt(tools: AgentTools) -> None:
    many = message("tool_use", *(use("get_release_history", {}) for _ in range(10)))
    many_again = message("tool_use", *(use("get_release_history", {}) for _ in range(10)))
    bad = submission(tools, suitability_assumptions=[])
    client = ScriptedClient([many, submit(bad), many_again, submit(submission(tools))])
    out = loop.recommend("legacy", tools, client, SETTINGS)

    results = tool_results(client.requests[1])
    assert [bool(r.get("is_error")) for r in results] == [False] * 8 + [True] * 2
    assert "budget" in results[-1]["content"]
    assert out.status == "validated"
    history_calls = [c for c in out.calls if c.name == "get_release_history"]
    assert len(history_calls) == 2 * config.MAX_TOOL_CALLS  # the budget resets per attempt


def test_request_cap_terminates_endless_tool_use(tools: AgentTools) -> None:
    client = ScriptedClient(lambda _: message("tool_use", use("get_release_history", {})))
    out = loop.recommend("legacy", tools, client, SETTINGS)
    assert len(client.requests) == config.MAX_LLM_REQUESTS_PER_PACKAGE
    assert out.status == "unresolved" and any("request limit" in e for e in out.errors)


def test_refusal_counts_as_failed_attempt(tools: AgentTools) -> None:
    details = {"type": "refusal", "category": "cyber", "explanation": None}
    client = ScriptedClient([message("refusal", stop_details=details), submit(submission(tools))])
    out = loop.recommend("legacy", tools, client, SETTINGS)
    assert out.status == "validated" and out.attempts == 2
    assert any("refusal" in e and "cyber" in e for e in out.errors)
    roles = [m["role"] for m in client.requests[1]["messages"]]
    assert roles == ["user", "user"]  # an empty assistant turn is not sent back


def test_end_turn_without_submit_counts_as_failed_attempt(tools: AgentTools) -> None:
    chat = message("end_turn", THINK, {"type": "text", "text": "I think it is fine."})
    client = ScriptedClient([chat, submit(submission(tools))])
    out = loop.recommend("legacy", tools, client, SETTINGS)
    assert out.status == "validated" and out.attempts == 2
    assert any("end_turn" in e for e in out.errors)
    last = client.requests[1]["messages"][-1]
    assert "submit_recommendation" in last["content"][0]["text"]


def test_max_tokens_with_partial_tool_use_gets_error_results(tools: AgentTools) -> None:
    cut = message("max_tokens", use("get_release_history", {}))
    client = ScriptedClient([cut, submit(submission(tools))])
    out = loop.recommend("legacy", tools, client, SETTINGS)
    (result,) = tool_results(client.requests[1])
    assert result["is_error"] is True
    assert out.status == "validated" and out.attempts == 2


def _api_error(cls: type[anthropic.APIStatusError], status: int) -> anthropic.APIStatusError:
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls("boom", response=httpx2.Response(status, request=request), body=None)


def test_auth_error_aborts_with_config_error(tools: AgentTools) -> None:
    client = ScriptedClient([_api_error(anthropic.AuthenticationError, 401)])
    with pytest.raises(ConfigError, match="uthentication"):
        loop.recommend("legacy", tools, client, SETTINGS)


def test_rate_limit_marks_package_unresolved(tools: AgentTools) -> None:
    client = ScriptedClient([_api_error(anthropic.RateLimitError, 429)])
    out = loop.recommend("legacy", tools, client, SETTINGS)
    assert out.status == "unresolved" and any("RateLimitError" in e for e in out.errors)


def test_run_agent_runs_each_package_in_rank_order(tools: AgentTools, mini_snapshot) -> None:
    ranked = analyze(mini_snapshot, list(REQS.values())).ranked
    client = ScriptedClient(lambda _: message("end_turn", {"type": "text", "text": "no"}))
    recs = loop.run_agent(ranked, tools, client, SETTINGS)
    assert [r.package for r in recs] == [s.name for s in ranked]
    assert all(r.status == "unresolved" for r in recs)
    assert all(c.package == r.package for r in recs for c in r.calls)

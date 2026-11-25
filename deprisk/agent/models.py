"""Agent-layer types: logged tool calls, validation input and recommendations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


@dataclass(frozen=True)
class ToolCall:
    """One logged tool call: who made it, where the data came from, and when it was fetched."""

    id: str
    package: str
    name: str
    args: Mapping[str, Any]
    output: Mapping[str, Any]
    source: Literal["snapshot", "live", "local"]
    origin: Literal["agent", "validation"]
    fetched_at: datetime | None


@dataclass(frozen=True)
class ValidationContext:
    """Everything the pure validator may read for one submission (SPEC §15)."""

    package: str
    profile: Mapping[str, Any]
    specifier: str
    calls: tuple[ToolCall, ...]
    t: datetime


@dataclass(frozen=True)
class Recommendation:
    """Final agent outcome for one package, validated or unresolved."""

    package: str
    status: Literal["validated", "unresolved"]
    output: Mapping[str, Any] | None
    attempts: int
    llm_requests: int
    errors: tuple[str, ...]
    calls: tuple[ToolCall, ...]
    model: str | None
    usage: Mapping[str, int]

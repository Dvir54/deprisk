"""Agent-layer types: logged tool calls, validation input and recommendations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from deprisk.data.models import FrozenModel


class ToolCall(FrozenModel):
    """One logged tool call: who made it, where the data came from, and when it was fetched."""

    id: str
    package: str
    name: str
    args: Mapping[str, Any]
    output: Mapping[str, Any]
    source: Literal["snapshot", "live", "local"]
    origin: Literal["agent", "validation"]
    fetched_at: datetime | None


class ValidationContext(FrozenModel):
    """Everything the pure validator may read for one submission (SPEC §15)."""

    package: str
    profile: Mapping[str, Any]
    specifier: str
    calls: tuple[ToolCall, ...]
    t: datetime


class Recommendation(FrozenModel):
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

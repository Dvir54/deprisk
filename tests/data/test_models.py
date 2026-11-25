"""Data types are immutable pydantic models sharing one base configuration."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from packaging.specifiers import SpecifierSet
from pydantic import BaseModel, ValidationError

from deprisk.agent import models as agent_models
from deprisk.data import models as data_models
from deprisk.data.models import FileInfo, FrozenModel, Requirement, VersionMeta
from deprisk.risk import models as risk_models

MODEL_CLASSES = [
    data_models.FileInfo,
    data_models.Advisory,
    data_models.VersionMeta,
    data_models.PackageRecord,
    data_models.Snapshot,
    data_models.Requirement,
    data_models.ParseIssue,
    risk_models.PackageSignals,
    risk_models.Placement,
    risk_models.Flag,
    risk_models.PackageScore,
    risk_models.Baseline,
    risk_models.AnalysisResult,
    agent_models.ToolCall,
    agent_models.ValidationContext,
    agent_models.Recommendation,
]


def sdist() -> FileInfo:
    return FileInfo(
        filename="pkg-1.0.tar.gz",
        packagetype="sdist",
        upload_time=datetime(2024, 1, 1, tzinfo=UTC),
        yanked=False,
        requires_python=None,
    )


@pytest.mark.parametrize("cls", MODEL_CLASSES, ids=lambda c: c.__name__)
def test_every_model_uses_the_shared_pydantic_base(cls: type) -> None:
    assert issubclass(cls, FrozenModel)
    assert issubclass(cls, BaseModel)


def test_models_are_immutable() -> None:
    f = sdist()
    with pytest.raises(ValidationError):
        f.yanked = True


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        FileInfo(**sdist().model_dump(), sha256="abc")


def test_null_metadata_stays_distinct_from_empty() -> None:
    absent = VersionMeta(classifiers=None, requires_dist=None, vulnerabilities=None)
    empty = VersionMeta(classifiers=(), requires_dist=(), vulnerabilities=())
    assert absent.requires_dist is None
    assert empty.requires_dist == ()
    assert absent != empty


def test_requirement_holds_a_specifier_set() -> None:
    req = Requirement(name="flask", specifier=SpecifierSet(">=2.0"), line="flask>=2.0")
    assert "2.1" in req.specifier

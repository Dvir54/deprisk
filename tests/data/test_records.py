"""Compact record extraction from PyPI JSON (SPEC §9.2, §11)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from deprisk.config import ADVISORY_SUMMARY_CHARS
from deprisk.data import records

FETCHED = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def raw_file(filename: str, upload: str = "2024-01-01T00:00:00.000000Z", **kw: Any) -> dict:
    return {
        "filename": filename,
        "packagetype": kw.pop("packagetype", "sdist"),
        "upload_time_iso_8601": upload,
        "yanked": kw.pop("yanked", False),
        "requires_python": kw.pop("requires_python", None),
        "digests": {"sha256": "x"},
        "size": 1,
        **kw,
    }


def project_json(**overrides: Any) -> dict:
    info = {
        "name": "My_Pkg",
        "version": "2.0",
        "classifiers": ["Programming Language :: Python :: 3.12"],
        "requires_dist": ["requests>=2"],
        "author": "Secret Author",
        "description": "Long free-text DESCRIPTION",
        **overrides.pop("info", {}),
    }
    body = {
        "info": info,
        "last_serial": 42,
        "ownership": {
            "organization": None,
            "roles": [{"role": "Owner", "user": "zed"}, {"role": "Maintainer", "user": "amy"}],
        },
        "releases": {
            "1.0": [raw_file("my_pkg-1.0.tar.gz", "2023-01-01T00:00:00Z")],
            "2.0": [raw_file("my_pkg-2.0.tar.gz", "2024-06-01T10:00:00.123456Z")],
        },
        "urls": [],
        "vulnerabilities": [],
    }
    body.update(overrides)
    return body


def test_extract_basic_fields() -> None:
    rec = records.extract_record(project_json(), FETCHED)
    assert rec.name == "my-pkg"
    assert rec.last_serial == 42
    assert rec.fetched_at == FETCHED
    assert rec.roles == (("Maintainer", "amy"), ("Owner", "zed"))
    assert rec.releases["2.0"][0].upload_time == datetime(2024, 6, 1, 10, 0, 0, 123456, tzinfo=UTC)
    assert set(rec.version_meta) == {"2.0"}
    assert rec.version_meta["2.0"].requires_dist == ("requests>=2",)
    assert rec.version_fetched_at == {"2.0": FETCHED}


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), ("not a list", None), ([], ()), (["a"], ("a",))],
)
def test_extract_keeps_null_distinct_from_empty(value: Any, expected: Any) -> None:
    body = project_json(info={"requires_dist": value, "classifiers": value})
    meta = records.extract_record(body, FETCHED).version_meta["2.0"]
    assert meta.requires_dist == expected
    assert meta.classifiers == expected


@pytest.mark.parametrize(("value", "expected"), [(None, None), ("x", None), ([], ())])
def test_vulnerabilities_null_distinct_from_empty(value: Any, expected: Any) -> None:
    meta = records.extract_record(project_json(vulnerabilities=value), FETCHED).version_meta["2.0"]
    assert meta.vulnerabilities == expected


def test_absent_metadata_fields_are_none() -> None:
    body = project_json()
    del body["info"]["requires_dist"], body["info"]["classifiers"], body["vulnerabilities"]
    meta = records.extract_record(body, FETCHED).version_meta["2.0"]
    assert (meta.classifiers, meta.requires_dist, meta.vulnerabilities) == (None, None, None)


def test_extract_drops_free_text_fields() -> None:
    dumped = records.extract_record(project_json(), FETCHED).model_dump_json()
    assert "Secret Author" not in dumped
    assert "DESCRIPTION" not in dumped
    assert "sha256" not in dumped


def test_non_string_requires_dist_entry_kept_as_text() -> None:
    """A non-string entry is kept (as text) so it is later counted as malformed, not dropped."""
    meta = records.extract_record(
        project_json(info={"requires_dist": ["six", 7]}), FETCHED
    ).version_meta["2.0"]
    assert meta.requires_dist == ("six", "7")


def test_advisory_fields_and_withdrawn_timestamp() -> None:
    vulns = [
        {
            "id": "GHSA-1",
            "aliases": ["CVE-1"],
            "fixed_in": ["2.1"],
            "withdrawn": None,
            "summary": "s" * 500,
            "details": "d",
        },
        {
            "id": "GHSA-2",
            "aliases": [],
            "fixed_in": [],
            "withdrawn": "2025-01-01T00:00:00Z",
            "summary": None,
            "details": "only details",
        },
    ]
    meta = records.extract_record(project_json(vulnerabilities=vulns), FETCHED).version_meta["2.0"]
    first, second = meta.vulnerabilities
    assert (first.id, first.aliases, first.fixed_in, first.withdrawn) == (
        "GHSA-1",
        ("CVE-1",),
        ("2.1",),
        False,
    )
    assert len(first.summary) == ADVISORY_SUMMARY_CHARS
    assert second.withdrawn is True
    assert second.summary == "only details"


def test_malformed_advisory_entry_kept_as_unknown() -> None:
    vulns = ["garbage", {"aliases": "x", "withdrawn": "not a date"}]
    meta = records.extract_record(project_json(vulnerabilities=vulns), FETCHED).version_meta["2.0"]
    assert [(a.id, a.withdrawn) for a in meta.vulnerabilities] == [
        ("unknown", False),
        ("unknown", False),
    ]


def test_file_with_unparseable_upload_time_dropped() -> None:
    body = project_json()
    body["releases"]["2.0"].append(raw_file("my_pkg-2.0-py3-none-any.whl", "yesterday"))
    rec = records.extract_record(body, FETCHED)
    assert [f.filename for f in rec.releases["2.0"]] == ["my_pkg-2.0.tar.gz"]


def test_add_version_meta() -> None:
    rec = records.extract_record(project_json(), FETCHED)
    later = datetime(2026, 11, 25, 13, 0, tzinfo=UTC)
    version_json = {
        "info": {"version": "1.0", "classifiers": [], "requires_dist": None},
        "vulnerabilities": [
            {"id": "PYSEC-1", "aliases": [], "fixed_in": ["2.0"], "withdrawn": None, "summary": "x"}
        ],
    }
    out = records.add_version_meta(rec, "1.0", version_json, later)
    assert out.version_meta["1.0"].classifiers == ()
    assert out.version_meta["1.0"].requires_dist is None
    assert out.version_meta["1.0"].vulnerabilities[0].id == "PYSEC-1"
    assert out.version_fetched_at["1.0"] == later
    assert "1.0" not in rec.version_meta  # the input record is unchanged


def test_as_of_drops_files_after_t() -> None:
    body = project_json()
    body["releases"]["2.0"].append(
        raw_file("my_pkg-2.0-py3-none-any.whl", "2026-01-01T00:00:00Z", packagetype="bdist_wheel")
    )
    body["releases"]["3.0"] = [raw_file("my_pkg-3.0.tar.gz", "2026-02-01T00:00:00Z")]
    body["releases"]["0.1"] = []
    rec = records.extract_record(body, FETCHED)
    view = records.as_of(rec, datetime(2025, 1, 1, tzinfo=UTC))
    assert [f.filename for f in view.releases["2.0"]] == ["my_pkg-2.0.tar.gz"]
    assert "3.0" not in view.releases  # every file was uploaded after t
    assert view.releases["0.1"] == ()  # file-less releases are kept as they were

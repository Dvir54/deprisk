"""Effective/reference versions and the S4/S5 ordinal states (SPEC §11, §12.2, §12.3; AC3).

The real-record fixtures in ``tests/fixtures/records/`` are compact records produced by
``deprisk.data.records.extract_record`` from the cached PyPI project JSON (2026-11-25).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

from deprisk.data.models import FileInfo, PackageRecord
from deprisk.risk import versions
from deprisk.risk.models import UnscorableError

ANY = SpecifierSet("")
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "records"
CP312_WHEEL = {
    "packagetype": "bdist_wheel",
    "filename": "pkg-{v}-cp312-cp312-manylinux_2_17_x86_64.whl",
}
PURE_WHEEL = {"packagetype": "bdist_wheel", "filename": "pkg-{v}-py3-none-any.whl"}
CLS_312 = "Programming Language :: Python :: 3.12"
CLS_38 = "Programming Language :: Python :: 3.8"


def wheel(template: dict, version: str, **extra: object) -> dict:
    return {**template, "filename": template["filename"].format(v=version), **extra}


def file(**kw: object) -> FileInfo:
    base = {
        "filename": "pkg-1.0.tar.gz",
        "packagetype": "sdist",
        "upload_time": datetime(2024, 1, 1, tzinfo=UTC),
        "yanked": False,
        "requires_python": None,
    }
    return FileInfo(**{**base, **kw})


def states(record, spec=ANY, meta=None) -> tuple[str | None, int, int]:
    eff = versions.effective_version(record, spec)
    return (
        eff,
        versions.install_path_state(record, eff),
        versions.py312_evidence_state(record, spec, eff, meta),
    )


def real_record(name: str) -> PackageRecord:
    return PackageRecord.model_validate_json((FIXTURES / f"{name}.json").read_text("utf-8"))


# --- real records (SPEC §12.2 verified cases) --------------------------------------------


def test_typing_effective_is_3_7_4_3() -> None:
    """typing 3.8+ releases declare requires_python excluding 3.12; pip falls back."""
    record = real_record("typing")
    assert versions.effective_version(record, ANY) == "3.7.4.3"
    assert versions.reference_version(record, ANY) == "3.7.4.3"
    assert versions.py312_evidence_state(record, ANY, "3.7.4.3", None) == 4


def test_futures_effective_is_3_0_5_via_sdist() -> None:
    record = real_record("futures")
    assert versions.effective_version(record, ANY) == "3.0.5"
    assert versions.install_path_state(record, "3.0.5") == 1  # only the sdist is eligible
    assert versions.py312_evidence_state(record, ANY, "3.0.5", None) == 4


def test_flask_effective_is_latest() -> None:
    record = real_record("flask")
    latest = str(versions.parse_final_versions(record.releases)[0][0])
    assert versions.effective_version(record, SpecifierSet(">=2.0")) == latest == "3.1.3"
    assert versions.install_path_state(record, latest) == 0


# --- eligibility -----------------------------------------------------------------


def test_musllinux_only_wheel_not_eligible(make_record) -> None:
    f = file(filename="pkg-1.0-cp312-cp312-musllinux_1_1_x86_64.whl", packagetype="bdist_wheel")
    assert not versions.file_is_eligible(f)
    record = make_record({"1.0": [{"packagetype": "bdist_wheel", "filename": f.filename}]})
    assert versions.effective_version(record, ANY) is None


def test_invalid_requires_python_not_admitted() -> None:
    assert not versions.file_admits_target(file(requires_python=">=3.6.*"))
    assert not versions.file_is_eligible(file(requires_python="not a specifier"))


@pytest.mark.parametrize("rp", [None, "", "  ", ">=3.8", ">=2.7,!=3.0.*"])
def test_unspecified_or_matching_requires_python_admitted(rp: str | None) -> None:
    assert versions.file_admits_target(file(requires_python=rp))


@pytest.mark.parametrize("rp", ["<3.12", ">=3.13", "==2.7.*"])
def test_excluding_requires_python_not_admitted(rp: str) -> None:
    assert not versions.file_admits_target(file(requires_python=rp))


def test_yanked_egg_and_unknown_types_not_eligible() -> None:
    assert not versions.file_is_eligible(file(yanked=True))
    assert not versions.file_is_eligible(
        file(filename="pkg-1.0-py3.12.egg", packagetype="bdist_egg")
    )
    assert not versions.file_is_eligible(file(filename="pkg-1.0.exe", packagetype="bdist_wininst"))
    assert not versions.file_is_eligible(file(filename="garbage.whl", packagetype="bdist_wheel"))


# --- parsing ---------------------------------------------------------------------


def test_invalid_versions_skipped_not_crash(make_record) -> None:
    record = make_record({"2005k": [{}], "2004.1": [{}], "2.0rc1": [{}], "1.0.dev3": [{}]})
    parsed = versions.parse_final_versions(record.releases)
    assert [s for _, s in parsed] == ["2004.1"]
    assert versions.count_skipped_versions(record.releases) == {"invalid": 1, "prerelease": 2}
    assert versions.effective_version(record, ANY) == "2004.1"


def test_parse_final_versions_descending_by_version_not_string(make_record) -> None:
    record = make_record({"1.9": [{}], "1.10": [{}], "1.0.post1": [{}]})
    assert [s for _, s in versions.parse_final_versions(record.releases)] == [
        "1.10",
        "1.9",
        "1.0.post1",
    ]


# --- effective and reference versions ----------------------------------------------


def test_effective_respects_specifier(make_record) -> None:
    record = make_record({"1.0": [{}], "2.0": [{}], "3.0": [{}]})
    assert versions.effective_version(record, SpecifierSet("<3")) == "2.0"
    assert versions.effective_version(record, ANY) == "3.0"


def test_effective_skips_release_whose_files_exclude_312(make_record) -> None:
    record = make_record({"1.0": [{}], "2.0": [{"requires_python": ">=3.13"}]})
    assert versions.effective_version(record, ANY) == "1.0"
    assert versions.reference_version(record, ANY) == "1.0"


def test_reference_is_newest_final_with_unyanked_file_when_no_effective(make_record) -> None:
    record = make_record(
        {
            "1.0": [{"requires_python": "<3"}],
            "2.0": [{"requires_python": "<3"}],
            "3.0": [{"yanked": True}],
            "4.0": [],
            "5.0b1": [{}],
        }
    )
    assert versions.effective_version(record, ANY) is None
    assert versions.reference_version(record, ANY) == "2.0"


def test_only_prereleases_unscored_with_reason(make_record) -> None:
    record = make_record({"1.0a1": [{}], "1.0rc1": [{}]})
    with pytest.raises(UnscorableError) as err:
        versions.reference_version(record, ANY)
    assert err.value.reason == "only pre-releases"


def test_only_yanked_unscored_with_reason(make_record) -> None:
    record = make_record({"1.0": [{"yanked": True}], "2.0": [{"yanked": True}]})
    with pytest.raises(UnscorableError) as err:
        versions.reference_version(record, ANY)
    assert err.value.reason == "only yanked files"


def test_no_files_unscored_with_reason(make_record) -> None:
    record = make_record({"1.0": [], "2.0": []})
    with pytest.raises(UnscorableError) as err:
        versions.reference_version(record, ANY)
    assert err.value.reason == "no files"


def test_no_valid_versions_unscored_with_reason(make_record) -> None:
    record = make_record({"2005k": [{}], "latest-ish": [{}]})
    with pytest.raises(UnscorableError) as err:
        versions.reference_version(record, ANY)
    assert err.value.reason == "no valid versions"


# --- S5 install path -----------------------------------------------------------------


def test_s5_state_0_eligible_wheel(make_record) -> None:
    record = make_record({"1.0": [{}, wheel(PURE_WHEEL, "1.0")]})
    assert states(record)[:2] == ("1.0", 0)


def test_s5_state_1_sdist_only(make_record) -> None:
    record = make_record(
        {"1.0": [{}, wheel(CP312_WHEEL, "1.0", requires_python="<3.12")]}  # wheel not eligible
    )
    assert states(record)[:2] == ("1.0", 1)


def test_s5_state_2_no_effective_version(make_record) -> None:
    record = make_record({"1.0": [{"requires_python": "<3"}]})
    assert states(record)[:2] == (None, 2)


# --- S4 Python 3.12 evidence ------------------------------------------------------------


def test_s4_state_0_classifier(make_record) -> None:
    record = make_record({"1.0": [{}]}, {"1.0": {"classifiers": [CLS_312]}})
    assert states(record, meta=record.version_meta["1.0"])[2] == 0


def test_s4_state_0_cp312_wheel(make_record) -> None:
    record = make_record({"1.0": [wheel(CP312_WHEEL, "1.0")]})
    assert states(record)[2] == 0


def test_s4_state_1_declared_requires_python(make_record) -> None:
    record = make_record({"1.0": [{"requires_python": ">=3.8"}]})
    assert states(record)[2] == 1


def test_s4_state_2_no_declaration_no_classifiers(make_record) -> None:
    record = make_record(
        {"1.0": [{"requires_python": ""}]},
        {"1.0": {"classifiers": ["Programming Language :: Python :: 3 :: Only"]}},
    )
    assert states(record, meta=record.version_meta["1.0"])[2] == 2


def test_s4_state_3_stale_classifiers(make_record) -> None:
    record = make_record({"1.0": [{}]}, {"1.0": {"classifiers": [CLS_38]}})
    assert states(record, meta=record.version_meta["1.0"])[2] == 3


def test_s4_state_4_pip_fallback(make_record) -> None:
    record = make_record({"1.0": [{}], "2.0": [{"requires_python": ">=3.13"}]})
    assert states(record) == ("1.0", 1, 4)


def test_s4_state_5_no_effective_version(make_record) -> None:
    record = make_record({"1.0": [{"requires_python": ">=3.13"}]})
    assert states(record)[2] == 5


def test_s4_fallback_with_312_classifier_is_4(make_record) -> None:
    record = make_record(
        {"1.0": [wheel(CP312_WHEEL, "1.0")], "2.0": [{"requires_python": "<3.12"}]},
        {"1.0": {"classifiers": [CLS_312]}},
    )
    assert states(record, meta=record.version_meta["1.0"]) == ("1.0", 0, 4)


def test_s4_fallback_ignores_newer_release_outside_specifier(make_record) -> None:
    record = make_record(
        {"1.0": [{"requires_python": ">=3.8"}], "2.0": [{"requires_python": "<3"}]}
    )
    assert states(record, spec=SpecifierSet("<2"))[2] == 1


def test_s4_fallback_ignores_newer_release_with_only_yanked_files(make_record) -> None:
    record = make_record({"1.0": [{"requires_python": ">=3.8"}], "2.0": [{"yanked": True}]})
    assert states(record)[2] == 1


def test_s4_declared_requires_python_with_stale_classifiers_is_1(make_record) -> None:
    record = make_record(
        {"1.0": [{"requires_python": ">=3.7"}]}, {"1.0": {"classifiers": [CLS_38]}}
    )
    assert states(record, meta=record.version_meta["1.0"])[2] == 1


def test_no_effective_version_gives_s5_2_s4_5(make_record) -> None:
    record = make_record(
        {
            "1.0": [
                {
                    "filename": "pkg-1.0-cp27-cp27mu-manylinux1_x86_64.whl",
                    "packagetype": "bdist_wheel",
                }
            ]
        },
        {"1.0": {"classifiers": [CLS_312]}},
    )
    assert states(record, meta=record.version_meta["1.0"]) == (None, 2, 5)
    assert versions.reference_version(record, ANY) == "1.0"


# --- release dates ------------------------------------------------------------------


def test_release_date_is_earliest_unyanked_upload() -> None:
    files = (
        file(upload_time=datetime(2023, 1, 1, tzinfo=UTC), yanked=True),
        file(upload_time=datetime(2023, 6, 1, tzinfo=UTC)),
        file(upload_time=datetime(2023, 3, 1, tzinfo=UTC)),
    )
    assert versions.release_date(files) == datetime(2023, 3, 1, tzinfo=UTC)
    assert versions.release_date((file(yanked=True),)) is None
    assert versions.release_date(()) is None


# --- P1 ---------------------------------------------------------------------------------


def test_cp311_only_wheel_not_eligible(make_record) -> None:
    name = "pkg-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    assert not versions.file_is_eligible(file(filename=name, packagetype="bdist_wheel"))
    record = make_record({"1.0": [{"filename": name, "packagetype": "bdist_wheel"}]})
    assert versions.effective_version(record, ANY) is None


def test_abi3_manylinux2014_wheel_eligible() -> None:
    name = "pkg-1.0-cp38-abi3-manylinux2014_x86_64.whl"
    assert versions.file_is_eligible(file(filename=name, packagetype="bdist_wheel"))


def test_abi3_wheel_alone_is_not_positive_evidence(make_record) -> None:
    record = make_record(
        {
            "1.0": [
                {
                    "filename": "pkg-1.0-cp38-abi3-manylinux_2_17_x86_64.whl",
                    "packagetype": "bdist_wheel",
                }
            ]
        }
    )
    assert states(record) == ("1.0", 0, 2)


def test_partially_yanked_release_still_eligible_via_unyanked_file(make_record) -> None:
    record = make_record(
        {"1.0": [{}], "2.0": [wheel(CP312_WHEEL, "2.0", yanked=True), {"requires_python": ">=3.8"}]}
    )
    assert states(record) == ("2.0", 1, 1)  # the yanked wheel is neither install path nor evidence


def test_upload_order_differs_from_version_order(make_record) -> None:
    """A backport (1.9.1) uploaded after 2.0 does not displace 2.0 as the effective version."""
    record = make_record(
        {
            "2.0": [{"upload_time": "2024-01-01T00:00:00+00:00"}],
            "1.9.1": [{"upload_time": "2025-06-01T00:00:00+00:00"}],
        }
    )
    assert versions.effective_version(record, ANY) == "2.0"
    assert versions.effective_version(record, SpecifierSet("<2")) == "1.9.1"

"""Signal values S1-S7 and evidence-only signals (SPEC §8, §11; AC3, AC4b)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from packaging.specifiers import SpecifierSet

from deprisk.data.models import SnapshotDataError
from deprisk.risk.signals import compute_signals

T = datetime(2026, 11, 25, tzinfo=UTC)
ANY = SpecifierSet("")
CLEAN = {"classifiers": [], "requires_dist": [], "vulnerabilities": []}


def at(days_before_t: float) -> str:
    return (T - timedelta(days=days_before_t)).isoformat()


def test_s1_uses_latest_upload_any_version(make_record) -> None:
    """A pre-release or an old-branch upload still shows the project is active."""
    rec = make_record(
        {
            "2.0": [{"upload_time": at(400)}],
            "1.9.1": [{"upload_time": at(100)}],
            "3.0b1": [{"upload_time": at(10.5)}],
        },
        {"2.0": CLEAN},
    )
    assert compute_signals(rec, ANY, T).values["S1"] == pytest.approx(10.5)


def test_s1_ignores_yanked_files(make_record) -> None:
    rec = make_record(
        {"1.0": [{"upload_time": at(300)}], "1.1": [{"upload_time": at(5), "yanked": True}]},
        {"1.0": CLEAN},
    )
    assert compute_signals(rec, ANY, T).values["S1"] == pytest.approx(300)


def test_s2_counts_final_releases_in_window_by_first_upload(make_record) -> None:
    rec = make_record(
        {
            "1.0": [
                {"upload_time": at(800)},
                {"upload_time": at(10)},
            ],  # released before the window
            "1.1": [{"upload_time": at(700)}],
            "1.2": [{"upload_time": at(20), "yanked": True}, {"upload_time": at(5)}],
            "1.3": [{"upload_time": at(3), "yanked": True}],  # fully yanked: not a release
            "2.0rc1": [{"upload_time": at(2)}],  # pre-release
            "2.0": [],  # no files
        },
        {"1.2": CLEAN},
    )
    assert compute_signals(rec, ANY, T).values["S2"] == 2  # 1.1 and 1.2


def test_s4_s5_from_version_logic(make_record) -> None:
    rec = make_record({"1.0": [{}], "2.0": [{"requires_python": ">=3.13"}]}, {"1.0": CLEAN})
    sig = compute_signals(rec, ANY, T)
    assert (sig.effective_version, sig.reference_version) == ("1.0", "1.0")
    assert (sig.values["S4"], sig.values["S5"]) == (4, 1)


def test_s6_excludes_withdrawn(make_record) -> None:
    vulns = [{"id": "A"}, {"id": "B", "withdrawn": True}, {"id": "C"}]
    rec = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "vulnerabilities": vulns}})
    sig = compute_signals(rec, ANY, T)
    assert sig.values["S6"] == 2
    assert sig.evidence["advisories"] == [
        {"id": "A", "aliases": [], "fixed_in": []},
        {"id": "C", "aliases": [], "fixed_in": []},
    ]


def test_s6_null_is_unknown_and_empty_is_zero(make_record) -> None:
    unknown = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "vulnerabilities": None}})
    empty = make_record({"1.0": [{}]}, {"1.0": CLEAN})
    assert compute_signals(unknown, ANY, T).values["S6"] is None
    assert "vulnerabilities" in compute_signals(unknown, ANY, T).evidence["missing"]
    assert compute_signals(empty, ANY, T).values["S6"] == 0


def test_s7_markers_and_extras_excluded(make_record) -> None:
    deps = [
        "requests>=2",
        'pywin32; sys_platform == "win32"',
        'pytest; extra == "test"',
        'typing-extensions; python_version < "3.12"',
        'tomli; python_version >= "3.11"',
    ]
    rec = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "requires_dist": deps}})
    sig = compute_signals(rec, ANY, T)
    assert sig.values["S7"] == 2
    assert sig.evidence["dependencies"] == ["requests", "tomli"]


def test_s7_distinct_normalised_names(make_record) -> None:
    deps = ["Foo_Bar>=1", 'foo-bar<3; python_version >= "3"', "foo.bar"]
    rec = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "requires_dist": deps}})
    assert compute_signals(rec, ANY, T).values["S7"] == 1


def test_s7_null_is_unknown_and_empty_is_zero(make_record) -> None:
    unknown = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "requires_dist": None}})
    excluded = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "requires_dist": ['x; extra == "a"']}})
    sig = compute_signals(unknown, ANY, T)
    assert sig.values["S7"] is None
    assert "requires_dist" in sig.evidence["missing"]
    assert compute_signals(excluded, ANY, T).values["S7"] == 0


def test_s7_malformed_entry_counted_and_marked_partial(make_record) -> None:
    deps = ["six", "not a valid requirement !!!", 'bad; python_version >>> "3"']
    rec = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "requires_dist": deps}})
    sig = compute_signals(rec, ANY, T)
    assert sig.values["S7"] == 3  # 1 valid + 2 malformed (cannot be shown not to apply)
    assert sig.partial == frozenset({"S7"})
    assert sig.evidence["malformed_requires_dist"] == deps[1:]


def test_no_effective_version_s6_s7_use_reference_version(make_record) -> None:
    rec = make_record(
        {"1.0": [{"requires_python": "<3"}], "2.0": [{"requires_python": "<3"}]},
        {
            "2.0": {
                "classifiers": [],
                "requires_dist": ["a", "b"],
                "vulnerabilities": [{"id": "X"}],
            },
            "1.0": {"classifiers": [], "requires_dist": [], "vulnerabilities": []},
        },
    )
    sig = compute_signals(rec, ANY, T)
    assert (sig.effective_version, sig.reference_version) == (None, "2.0")
    assert (sig.values["S4"], sig.values["S5"]) == (5, 2)
    assert (sig.values["S6"], sig.values["S7"]) == (1, 2)


def test_missing_version_meta_raises_snapshot_data_error(make_record) -> None:
    rec = make_record({"1.0": [{}], "2.0": [{}]}, {"1.0": CLEAN})  # reference 2.0 has no meta
    with pytest.raises(SnapshotDataError):
        compute_signals(rec, ANY, T)


def test_evidence_only_signals(make_record) -> None:
    rec = make_record(
        {
            "0.8": [{"upload_time": at(500), "yanked": True}],
            "0.9": [{"upload_time": at(200)}],
        },
        {
            "0.9": {
                **CLEAN,
                "classifiers": ["Development Status :: 7 - Inactive"],
            }
        },
    )
    rec = rec.model_copy(update={"roles": (("Owner", "a"), ("Maintainer", "b"))})
    ev = compute_signals(rec, ANY, T).evidence
    assert ev["S3"] == pytest.approx(200)
    assert ev["S8"] == 2
    assert ev["S9"] == pytest.approx(0.5)
    assert ev["S10"] is True
    assert ev["S14"] is True


def test_values_cover_every_scored_signal(make_record) -> None:
    rec = make_record({"1.0": [{}]}, {"1.0": CLEAN})
    assert set(compute_signals(rec, ANY, T).values) == {"S1", "S2", "S4", "S5", "S6", "S7"}


def test_evidence_records_the_specifier(make_record) -> None:
    rec = make_record({"1.0": [{}], "2.0": [{}]}, {"1.0": CLEAN})
    assert compute_signals(rec, SpecifierSet("<2,>=1"), T).evidence["specifier"] == "<2,>=1"

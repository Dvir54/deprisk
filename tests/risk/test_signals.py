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


# --- S6 advisory deduplication (approved by the user after M5) ----------------------------


def s6(make_record, vulns: list[dict]):
    rec = make_record({"1.0": [{}]}, {"1.0": {**CLEAN, "vulnerabilities": vulns}})
    return compute_signals(rec, ANY, T)


def test_s6_counts_pysec_and_ghsa_aliases_once(make_record) -> None:
    """PyPI lists one vulnerability under several ids (pycrypto: 4 entries, 2 CVEs)."""
    vulns = [
        {"id": "PYSEC-2017-94", "aliases": ["CVE-2013-7459", "GHSA-cq27"]},
        {"id": "GHSA-cq27", "aliases": ["CVE-2013-7459", "PYSEC-2017-94"]},
        {"id": "PYSEC-2018-97", "aliases": ["CVE-2018-6594", "GHSA-6528"]},
        {"id": "GHSA-6528", "aliases": ["CVE-2018-6594", "PYSEC-2018-97"]},
    ]
    sig = s6(make_record, vulns)
    assert sig.values["S6"] == 2
    assert [g["ids"] for g in sig.evidence["advisory_groups"]] == [
        ["GHSA-6528", "PYSEC-2018-97"],
        ["GHSA-cq27", "PYSEC-2017-94"],
    ]
    assert len(sig.evidence["advisories"]) == 4  # the original records stay available


def test_s6_shared_alias_only_links_entries(make_record) -> None:
    """Two entries that never name each other but share a CVE are one vulnerability."""
    vulns = [{"id": "PYSEC-1", "aliases": ["CVE-1"]}, {"id": "GHSA-1", "aliases": ["CVE-1"]}]
    assert s6(make_record, vulns).values["S6"] == 1


def test_s6_overlapping_aliases_merge_transitively(make_record) -> None:
    """A-B share CVE-1 and B-C share CVE-2, so A, B and C are one group; D stays apart."""
    vulns = [
        {"id": "A", "aliases": ["CVE-1"]},
        {"id": "B", "aliases": ["CVE-1", "CVE-2"]},
        {"id": "C", "aliases": ["CVE-2"]},
        {"id": "D", "aliases": ["CVE-9"]},
    ]
    sig = s6(make_record, vulns)
    assert sig.values["S6"] == 2
    groups = sig.evidence["advisory_groups"]
    assert groups[0] == {"ids": ["A", "B", "C"], "aliases": ["CVE-1", "CVE-2"], "fixed_in": []}
    assert groups[1]["ids"] == ["D"]


def test_s6_group_order_independent_of_entry_order(make_record) -> None:
    vulns = [
        {"id": "C", "aliases": ["CVE-2"]},
        {"id": "D", "aliases": []},
        {"id": "A", "aliases": ["CVE-1"]},
        {"id": "B", "aliases": ["CVE-1", "CVE-2"]},
    ]
    forward = s6(make_record, vulns).evidence["advisory_groups"]
    backward = s6(make_record, list(reversed(vulns))).evidence["advisory_groups"]
    assert forward == backward


def test_s6_repeated_id_counts_once(make_record) -> None:
    vulns = [{"id": "GHSA-x", "fixed_in": ["1.1"]}, {"id": "GHSA-x", "fixed_in": ["1.2"]}]
    sig = s6(make_record, vulns)
    assert sig.values["S6"] == 1
    assert sig.evidence["advisory_groups"][0]["fixed_in"] == ["1.1", "1.2"]


def test_s6_unknown_ids_never_merge(make_record) -> None:
    """Malformed entries (id "unknown", no aliases) cannot be shown to be the same
    vulnerability, so each still counts (the riskier reading)."""
    vulns = [
        {"id": "unknown"},
        {"id": "unknown"},
        {"id": "unknown", "aliases": ["CVE-7"]},
        {"id": "X", "aliases": ["CVE-7"]},
    ]
    assert s6(make_record, vulns).values["S6"] == 3


def test_s6_withdrawn_entries_excluded_before_grouping(make_record) -> None:
    vulns = [
        {"id": "PYSEC-1", "aliases": ["CVE-1"], "withdrawn": True},
        {"id": "GHSA-1", "aliases": ["CVE-1"]},
        {"id": "GHSA-2", "aliases": ["CVE-2"], "withdrawn": True},
    ]
    sig = s6(make_record, vulns)
    assert sig.values["S6"] == 1
    assert sig.evidence["advisory_groups"] == [
        {"ids": ["GHSA-1"], "aliases": ["CVE-1"], "fixed_in": []}
    ]


def test_s6_group_fix_is_union_of_member_fixes(make_record) -> None:
    vulns = [
        {"id": "PYSEC-1", "aliases": ["GHSA-1"], "fixed_in": []},
        {"id": "GHSA-1", "fixed_in": ["2.0"]},
    ]
    assert s6(make_record, vulns).evidence["advisory_groups"][0]["fixed_in"] == ["2.0"]

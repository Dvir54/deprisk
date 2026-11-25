"""requirements.txt parsing (FR1): names, specifiers, comments, unsupported lines."""

from __future__ import annotations

from pathlib import Path

import pytest

from deprisk.config import ConfigError
from deprisk.data.requirements import parse_requirements

ASSIGNMENT = Path(__file__).resolve().parents[2] / "assignment" / "requirements.txt"


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    return path


def test_parses_assignment_file_40_packages() -> None:
    reqs, issues = parse_requirements(ASSIGNMENT)
    assert len(reqs) == 40
    assert issues == []
    by_name = {r.name: r for r in reqs}
    assert str(by_name["flask"].specifier) == ">=2.0"
    assert str(by_name["typing"].specifier) == ""
    assert reqs[0].name == "flask" and reqs[-1].name == "mock"  # file order kept


def test_normalises_names(tmp_path: Path) -> None:
    reqs, issues = parse_requirements(
        write(tmp_path, "PyYAML>=5.4\nJinja2\nfoo_bar\nZope.Interface==5\n")
    )
    assert [r.name for r in reqs] == ["pyyaml", "jinja2", "foo-bar", "zope-interface"]
    assert reqs[0].line == "PyYAML>=5.4"
    assert issues == []


def test_reports_unsupported_lines(tmp_path: Path) -> None:
    text = "\n".join(
        [
            "six",
            "-r other.txt",
            "-e git+https://github.com/x/y.git#egg=y",
            "--index-url https://example.org/simple",
            "https://example.org/pkg-1.0.tar.gz",
            "pkg @ https://example.org/pkg-1.0.tar.gz",
            "not a requirement !!!",
            "SIX>=1",
        ]
    )
    reqs, issues = parse_requirements(write(tmp_path, text))
    assert [r.name for r in reqs] == ["six"]
    assert [(i.line_no, i.reason.split(":")[0]) for i in issues] == [
        (2, "unsupported option"),
        (3, "unsupported option"),
        (4, "unsupported option"),
        (5, "invalid requirement"),
        (6, "direct URL reference"),
        (7, "invalid requirement"),
        (8, "duplicate of line 1"),
    ]


def test_inline_comment_and_marker(tmp_path: Path) -> None:
    text = '# header\n\nrequests>=2.25  # HTTP\nenum34; python_version < "3.4"\nfoo[extra]>=1\n'
    reqs, issues = parse_requirements(write(tmp_path, text))
    assert [(r.name, str(r.specifier)) for r in reqs] == [
        ("requests", ">=2.25"),
        ("enum34", ""),
        ("foo", ">=1"),
    ]
    assert reqs[0].line == "requests>=2.25"
    assert issues == []


def test_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse_requirements(tmp_path / "absent.txt")

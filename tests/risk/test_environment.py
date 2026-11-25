"""Fixed target environment: accepted wheel tags and marker evaluation (SPEC §12.1)."""

from __future__ import annotations

import pytest
from packaging.markers import Marker
from packaging.tags import Tag

from deprisk.risk import environment


def test_accepted_tags_fixed_and_host_independent() -> None:
    tags = environment.ACCEPTED_TAGS
    for wanted in (
        "cp312-cp312-manylinux_2_17_x86_64",
        "cp312-abi3-manylinux2014_x86_64",
        "cp312-cp312-manylinux_2_5_x86_64",
        "py3-none-any",
    ):
        interpreter, abi, platform = wanted.split("-")
        assert Tag(interpreter, abi, platform) in tags, wanted
    for tag in tags:
        assert not any(bad in tag.platform for bad in ("win", "macosx", "musllinux")), tag
    assert environment.build_accepted_tags() == tags


def test_accepted_tags_exclude_other_pythons_and_newer_glibc() -> None:
    tags = environment.ACCEPTED_TAGS
    assert Tag("cp311", "cp311", "manylinux_2_17_x86_64") not in tags
    assert Tag("cp313", "cp313", "manylinux_2_17_x86_64") not in tags
    assert Tag("cp312", "cp312", "manylinux_2_38_x86_64") not in tags
    assert Tag("cp312", "cp312", "manylinux_2_17_aarch64") not in tags


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ('sys_platform == "win32"', False),
        ('python_version < "3.12"', False),
        ('python_full_version >= "3.12.0"', True),
        ('extra == "dev"', False),
        ('platform_system == "Linux" and platform_machine == "x86_64"', True),
        ('os_name == "nt"', False),
        ('implementation_name == "cpython"', True),
    ],
)
def test_marker_env_evaluates_linux_312(marker: str, expected: bool) -> None:
    assert environment.marker_applies(Marker(marker)) is expected


def test_marker_env_has_extra_and_every_config_key() -> None:
    env = environment.MARKER_ENV
    assert env["extra"] == ""
    assert env["sys_platform"] == "linux"

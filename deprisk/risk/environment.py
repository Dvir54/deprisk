"""The fixed target environment: accepted wheel tags and marker evaluation (SPEC §12.1).

Nothing here reads the host machine: tags are built from config with ``packaging.tags``
(never ``sys_tags()``), and markers are evaluated against a complete fixed environment.
"""

from __future__ import annotations

from collections.abc import Mapping

from packaging.markers import Marker
from packaging.tags import Tag, compatible_tags, cpython_tags

from deprisk import config

_INTERPRETER = f"cp{config.PYTHON_VERSION[0]}{config.PYTHON_VERSION[1]}"


def _platforms() -> list[str]:
    """manylinux platforms for the target glibc, newest first, then the legacy aliases."""
    perennial = [f"manylinux_2_{m}_{config.PLATFORM_ARCH}" for m in config.MANYLINUX_GLIBC_MINORS]
    legacy = [f"{name}_{config.PLATFORM_ARCH}" for name in config.LEGACY_MANYLINUX]
    return perennial + legacy


def build_accepted_tags() -> frozenset[Tag]:
    """Every wheel tag pip on the target environment would accept (cp312, abi3, py3, any)."""
    platforms = _platforms()
    tags = set(
        cpython_tags(
            python_version=config.PYTHON_VERSION,
            abis=[_INTERPRETER, "abi3", "none"],
            platforms=platforms,
        )
    )
    tags.update(
        compatible_tags(
            python_version=config.PYTHON_VERSION,
            interpreter=_INTERPRETER,
            platforms=platforms,
        )
    )
    return frozenset(tags)


ACCEPTED_TAGS: frozenset[Tag] = build_accepted_tags()

# Requirements are evaluated outside any extra, so `extra == "..."` markers never apply.
MARKER_ENV: Mapping[str, str] = {**config.MARKER_ENV, "extra": ""}


def marker_applies(marker: Marker) -> bool:
    """Whether a PEP 508 marker holds on the target environment (host-independent)."""
    return marker.evaluate(dict(MARKER_ENV))

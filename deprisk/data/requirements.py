"""requirements.txt parsing (FR1).

Supported: one PEP 508 requirement per line, with comments and blank lines. Options
(``-r``, ``-e``, ``--index-url``, ...), direct URL references, invalid lines and
duplicate names are reported as ParseIssues, never silently skipped. Names are
PEP 503-normalised. Extras and markers are accepted but not used for scoring.
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as PEP508Requirement
from packaging.utils import canonicalize_name

from deprisk.config import ConfigError
from deprisk.data.models import ParseIssue, Requirement

_COMMENT = re.compile(r"(^|\s)#.*$")  # pip: '#' starts a comment at line start or after space


def parse_requirements(path: Path) -> tuple[list[Requirement], list[ParseIssue]]:
    """Requirements in file order plus every line that was not used, with the reason."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read requirements file {path}: {exc}") from exc

    requirements: list[Requirement] = []
    issues: list[ParseIssue] = []
    first_line: dict[str, int] = {}
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = _COMMENT.sub("", raw).strip()
        if not line:
            continue
        if line.startswith("-"):
            issues.append(
                ParseIssue(line_no=line_no, line=line, reason="unsupported option: not followed")
            )
            continue
        try:
            parsed = PEP508Requirement(line)
        except InvalidRequirement as exc:
            issues.append(
                ParseIssue(line_no=line_no, line=line, reason=f"invalid requirement: {exc}")
            )
            continue
        if parsed.url:
            issues.append(
                ParseIssue(line_no=line_no, line=line, reason="direct URL reference: not on PyPI")
            )
            continue
        name = canonicalize_name(parsed.name)
        if name in first_line:
            issues.append(
                ParseIssue(
                    line_no=line_no, line=line, reason=f"duplicate of line {first_line[name]}"
                )
            )
            continue
        first_line[name] = line_no
        requirements.append(Requirement(name=name, specifier=parsed.specifier, line=line))
    return requirements, issues

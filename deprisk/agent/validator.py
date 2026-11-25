"""Pure recommendation validator (SPEC §15).

Checks facts only: it reads the ``ValidationContext`` (tool calls already logged) and
``sys.stdlib_module_names``, and never fetches. A fact missing from the context is an
error ("missing evidence"), never a reason to look it up. It does not judge whether a
recommendation is functionally suitable.

Recommendation fields read here (the submit schema, M7): ``action`` (upgrade, pin,
replace, do_nothing), ``target`` (``>=V``; ``==V`` or ``<V``; a project or module name),
``replacement_type`` (``pypi`` or ``stdlib`` for replace), ``finding``, ``evidence``
(items ``{call_id, field, value}``; ``field`` is a dotted path such as
``vulnerabilities[0].id`` into the cited call's output) and ``suitability_assumptions``.

Findings are a flag code of the package, one of its top-2 signal contributions, or a
requirement-context fact (``spec_spans_major``, ``spec_allows_advisories``) that a logged
``get_requirement`` output reports as true. Evidence must cite the agent's own calls;
facts about V or a candidate come from the calls made by evidence collection.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from deprisk.agent.models import ToolCall, ValidationContext
from deprisk.risk.signals import group_advisories

ACTIONS = ("upgrade", "pin", "replace", "do_nothing")
S16_FACTS = ("spec_spans_major", "spec_allows_advisories")
# A replacement candidate must carry none of these flags (SPEC §15).
REPLACEMENT_BLOCKERS = (
    "no_eligible_version",
    "python_fallback",
    "unfixed_advisory",
    "advisory_with_fix",
)

# Output fields (dotted paths, list indices removed) that can support each finding. A
# profile ``flags[i]`` item also supports the finding equal to that flag's code.
_ADVISORY_FIELDS = (
    "signals.S6",
    "evidence.advisories",
    "evidence.advisory_groups",
    "vulnerabilities",
)
FINDING_FIELDS: Mapping[str, tuple[str, ...]] = {
    "S1": ("signals.S1", "evidence.last_upload"),
    "S2": ("signals.S2",),
    "S4": ("signals.S4", "effective_version", "eligible", "versions.eligible", "requires_python"),
    "S5": ("signals.S5", "effective_version", "eligible", "versions.eligible", "files"),
    "S6": _ADVISORY_FIELDS,
    "S7": (
        "signals.S7",
        "evidence.dependencies",
        "evidence.malformed_requires_dist",
        "requires_dist",
    ),
    "no_eligible_version": ("signals.S5", "effective_version", "eligible", "versions.eligible"),
    "python_fallback": ("signals.S4", "effective_version", "eligible", "versions.eligible"),
    "sdist_only": ("signals.S5", "files", "eligible_files"),
    "unfixed_advisory": _ADVISORY_FIELDS,
    "advisory_with_fix": _ADVISORY_FIELDS,
    "missing:requires_dist": ("signals.S7", "evidence.missing", "requires_dist"),
    "missing:vulnerabilities": ("signals.S6", "evidence.missing", "vulnerabilities"),
    "beyond_baseline_range": ("beyond_baseline_range",),
    "spec_spans_major": ("spec_spans_major", "allowed_majors"),
    "spec_allows_advisories": ("spec_allows_advisories", "floor_vulnerabilities"),
}
# Fields whose cited values name advisory ids (``id``, ``ids`` or ``aliases`` leaves).
ADVISORY_ID_FIELDS = (
    "vulnerabilities",
    "floor_vulnerabilities",
    "evidence.advisories",
    "evidence.advisory_groups",
    "flags.evidence.vulnerabilities",
)
_PROJECT_WIDE = ("S1", "S2")  # no version excludes a maintenance problem

_BOUND = re.compile(r"^\s*(>=|==|<)\s*([^\s,;]+)\s*$")
_PATH = re.compile(r"[^.\[\]]+(\[\d+\])*(\.[^.\[\]]+(\[\d+\])*)*")
_PATH_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
_PROJECT_NAME = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
_MODULE_NAME = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$")
_MISSING = object()

Item = tuple[ToolCall, str, Any]  # a checked evidence item: (cited call, field, value)


# --- target helpers (shared with tools.collect_validation_evidence) ---------------------


def parse_bound(target: str) -> tuple[str, str] | None:
    """``(operator, version)`` of an ``>=V``, ``==V`` or ``<V`` target; None otherwise."""
    match = _BOUND.match(target or "")
    if match is None:
        return None
    try:
        Version(match.group(2))
    except InvalidVersion:
        return None
    return match.group(1), match.group(2)


def highest_allowed_below(eligible_output: Mapping[str, Any], bound: str) -> str | None:
    """Highest currently allowed version below ``bound`` in a find_eligible_versions output."""
    limit = Version(bound)
    below = [
        v["version"]
        for v in eligible_output.get("versions", [])
        if v["allowed"] and Version(v["version"]) < limit
    ]
    return max(below, key=Version) if below else None


# --- evidence helpers -------------------------------------------------------------------


def _resolve(output: Mapping[str, Any], field: str) -> Any:
    """The value at a dotted path such as ``vulnerabilities[0].id``, or ``_MISSING``."""
    if not isinstance(field, str) or not _PATH.fullmatch(field):
        return _MISSING
    current: Any = output
    for key, index in _PATH_PART.findall(field):
        if key:
            if not isinstance(current, Mapping) or key not in current:
                return _MISSING
            current = current[key]
        else:
            i = int(index)
            if isinstance(current, str) or not isinstance(current, Sequence) or i >= len(current):
                return _MISSING
            current = current[i]
    return current


def _normalise(field: str) -> str:
    return re.sub(r"\[\d+\]", "", field)


def _under(path: str, roots: Sequence[str]) -> bool:
    return any(path == r or path.startswith(r + ".") for r in roots)


def _matches(cited: Any, actual: Any) -> bool:
    """Whether a cited value equals the logged one (numbers and JSON text are accepted)."""
    if isinstance(actual, bool) or isinstance(cited, bool):
        if isinstance(cited, str):
            return cited.strip().lower() == json.dumps(actual)
        return isinstance(cited, bool) and isinstance(actual, bool) and cited == actual
    if isinstance(actual, int | float):
        try:
            return math.isclose(float(cited), float(actual), rel_tol=1e-9, abs_tol=1e-6)
        except (TypeError, ValueError):
            return False
    if cited == actual:
        return True
    if isinstance(cited, str) and not isinstance(actual, str):
        try:
            return json.loads(cited) == actual
        except ValueError:
            return False
    return False


def _check_evidence(raw: Any, ctx: ValidationContext) -> tuple[list[Item], list[str]]:
    """Every item must cite an agent call for this package and match its logged output."""
    if not isinstance(raw, Sequence) or isinstance(raw, str) or not raw:
        return [], ["evidence: at least one item is required"]
    calls = {c.id: c for c in ctx.calls}
    items: list[Item] = []
    errors: list[str] = []
    for i, item in enumerate(raw):
        where = f"evidence[{i}]"
        if not isinstance(item, Mapping) or not {"call_id", "field", "value"} <= set(item):
            errors.append(f"{where}: an item needs call_id, field and value")
            continue
        call = calls.get(item["call_id"])
        if call is None:
            errors.append(f"{where}: unknown call id {item['call_id']!r} (not in the tool log)")
        elif call.package != ctx.package:
            errors.append(f"{where}: call {call.id} is about another package ({call.package})")
        elif call.origin != "agent":
            errors.append(f"{where}: call {call.id} was made by validation, not by the agent")
        elif (actual := _resolve(call.output, item["field"])) is _MISSING:
            errors.append(f"{where}: field {item['field']!r} not found in call {call.id}'s output")
        elif not _matches(item["value"], actual):
            errors.append(
                f"{where}: value {item['value']!r} does not match {item['field']} = "
                f"{actual!r} in call {call.id}"
            )
        else:
            items.append((call, item["field"], item["value"]))
    return items, errors


def _supports(item: Item, finding: str) -> bool:
    """Whether an evidence item is about the finding (see ``FINDING_FIELDS``)."""
    call, field, _ = item
    if call.name == "lookup_candidate":  # about the candidate, not the package
        return False
    path = _normalise(field)
    flag = re.match(r"flags\[(\d+)\]", field)
    if flag and call.name == "get_package_profile":
        flags = call.output.get("flags", [])
        index = int(flag.group(1))
        return index < len(flags) and flags[index].get("code") == finding
    roots = FINDING_FIELDS.get(
        finding, ("evidence.missing",) if finding.startswith("missing:") else ()
    )
    return _under(path, roots)


def _ids_in(value: Any, leaf: str) -> set[str]:
    if isinstance(value, str):
        return {value} if leaf in ("id", "ids", "aliases") else set()
    if isinstance(value, Mapping):
        return set().union(*(_ids_in(value.get(k), k) for k in ("id", "ids", "aliases")))
    if isinstance(value, Sequence):
        return set().union(set(), *(_ids_in(v, leaf) for v in value))
    return set()


def _cited_ids(items: Sequence[Item]) -> set[str]:
    """Advisory ids or aliases named by the evidence values."""
    ids: set[str] = set()
    for _, field, value in items:
        path = _normalise(field)
        if _under(path, ADVISORY_ID_FIELDS):
            ids |= _ids_in(value, path.rsplit(".", 1)[-1])
    return ids


def _known_vulnerabilities(ctx: ValidationContext) -> list[dict[str, Any]]:
    """Deduplicated vulnerabilities over every advisory entry in the context (D17)."""
    entries = list(ctx.profile.get("evidence", {}).get("advisories", []))
    for call in ctx.calls:
        for key in ("vulnerabilities", "floor_vulnerabilities"):
            if call.name != "lookup_candidate" and isinstance(call.output.get(key), list):
                entries.extend(call.output[key])
    return group_advisories(
        [
            {"id": e["id"], "aliases": list(e.get("aliases", [])), "fixed_in": []}
            for e in entries
            if isinstance(e, Mapping) and isinstance(e.get("id"), str)
        ]
    )


def _expand(ids: set[str], ctx: ValidationContext) -> set[str]:
    """``ids`` plus every id and alias of the vulnerabilities they name."""
    expanded = set(ids)
    for group in _known_vulnerabilities(ctx):
        members = {*group["ids"], *group["aliases"]}
        if members & ids:
            expanded |= members
    return expanded


def _subject_version(item: Item) -> str | None:
    """The release an evidence item is about, if any."""
    call, field, _ = item
    out = call.output
    if call.name == "get_version_details":
        return out.get("version")
    if call.name == "get_package_profile":
        return out.get("reference_version")
    if call.name == "find_eligible_versions":
        match = re.match(r"versions\[(\d+)\]", field)
        listed = out.get("versions", [])
        if match and int(match.group(1)) < len(listed):
            return listed[int(match.group(1))].get("version")
    if call.name == "get_requirement" and (
        field.startswith("floor_") or field == "spec_allows_advisories"
    ):
        return out.get("floor_version")
    return None


def _shows_problem(item: Item) -> bool:
    """Advisory fields must name an advisory; eligibility/yank fields must show the bad value."""
    call, field, _ = item
    path = _normalise(field)
    leaf = path.rsplit(".", 1)[-1]
    actual = _resolve(call.output, field)
    if _under(path, ADVISORY_ID_FIELDS):
        return bool(_cited_ids([item]))
    if leaf == "eligible":
        return actual is False
    if leaf == "yanked":
        return actual is True
    return True


def _as_version(text: Any) -> Version | None:
    try:
        return Version(str(text))
    except InvalidVersion:
        return None


def _in_excluded(finding: str, supporting: Sequence[Item], excluded: set[Version]) -> bool:
    """Whether some supporting item shows the problem in a version the new bound excludes."""
    if finding in _PROJECT_WIDE:
        return False
    return any(
        (v := _as_version(_subject_version(item))) is not None
        and v in excluded
        and _shows_problem(item)
        for item in supporting
    )


def top_signals(profile: Mapping[str, Any]) -> list[str]:
    """The two largest positive signal contributions (ties: signal id order)."""
    positive = [
        (s, entry["contribution"])
        for s, entry in profile.get("signals", {}).items()
        if entry.get("contribution", 0) > 0
    ]
    return [s for s, _ in sorted(positive, key=lambda p: (-p[1], p[0]))[:2]]


def _validation_output(
    ctx: ValidationContext, name: str, matches: Callable[[Mapping[str, Any]], bool]
) -> Mapping[str, Any] | None:
    """Output of the latest evidence-collection call ``name`` whose args satisfy ``matches``."""
    for call in reversed(ctx.calls):
        if (
            call.origin == "validation"
            and call.package == ctx.package
            and call.name == name
            and matches(call.args)
        ):
            return call.output
    return None


def _spec_floor(specifier: str) -> Version | None:
    """The specifier's lower bound (``>=``, ``>``, ``~=``, ``==``), if it has one."""
    try:
        spec = SpecifierSet(specifier)
    except InvalidSpecifier:
        return None
    floors = [
        v
        for s in spec
        if s.operator in (">=", ">", "~=", "==", "===")
        and (v := _as_version(s.version.removesuffix(".*"))) is not None
    ]
    return max(floors) if floors else None


# --- per-action rules -------------------------------------------------------------------


def _version_facts(
    ctx: ValidationContext, version: str
) -> tuple[Mapping[str, Any] | None, list[str]]:
    """The collected get_version_details output for ``version`` and its existence errors."""
    wanted = Version(version)
    details = _validation_output(
        ctx, "get_version_details", lambda a: _as_version(a.get("version")) == wanted
    )
    if details is None:
        return None, [f"missing evidence: no details were collected for version {version}"]
    if "error" in details:
        return None, [f"version {version} does not exist: {details['error']}"]
    errors = []
    if details.get("yanked") is not False:
        errors.append(f"version {version} is yanked (or its files are unknown)")
    if details.get("eligible") is not True:
        errors.append(f"version {version} is not eligible on CPython 3.12 Linux x86_64")
    return details, errors


def _eligible_facts(ctx: ValidationContext) -> tuple[Mapping[str, Any] | None, list[str]]:
    eligible = _validation_output(ctx, "find_eligible_versions", lambda a: True)
    if eligible is None or "error" in eligible:
        return None, ["missing evidence: the package's eligible versions were not collected"]
    return eligible, []


def _allowed(eligible: Mapping[str, Any]) -> list[Version]:
    return [Version(v["version"]) for v in eligible.get("versions", []) if v["allowed"]]


def _not_addressed(finding: str, excluded: set[Version]) -> str:
    if finding in _PROJECT_WIDE:
        return (
            f"the action does not address finding {finding!r}: it measures the whole project, "
            "so no version bound changes it"
        )
    listed = ", ".join(str(v) for v in sorted(excluded)) or "none"
    return (
        f"the action does not address finding {finding!r}: no supporting evidence shows a "
        f"problem in the excluded versions ({listed})"
    )


def _check_upgrade(
    rec: Mapping[str, Any], ctx: ValidationContext, finding: str | None, items: list[Item]
) -> list[str]:
    bound = parse_bound(str(rec.get("target") or ""))
    if bound is None or bound[0] != ">=":
        return [f"target: an upgrade needs a concrete '>=V' target, got {rec.get('target')!r}"]
    text = bound[1]
    target = Version(text)
    eligible, errors = _eligible_facts(ctx)
    details, version_errors = _version_facts(ctx, text)
    errors += version_errors
    if details is not None:
        if details.get("is_final") is not True:
            errors.append(f"version {text} is not a final release")
        if details.get("satisfies_specifier") is not True:
            errors.append(
                f"version {text} does not satisfy the current specifier {ctx.specifier!r}"
            )
    if eligible is None:
        return errors

    allowed = _allowed(eligible)
    floor = _spec_floor(ctx.specifier) or _as_version(eligible.get("oldest_allowed_version"))
    excluded = {v for v in allowed if v < target}
    if floor is None or target <= floor:
        errors.append(f"the upgrade must raise the current floor ({floor}): {text} does not")
    elif not excluded:
        errors.append(f">={text} excludes no currently allowed release")

    if finding is not None:
        supporting = [i for i in items if _supports(i, finding)]
        if finding == "spec_spans_major":
            addressed = bool(allowed) and target.major > min(v.major for v in allowed)
        else:
            addressed = _in_excluded(finding, supporting, excluded)
        if not addressed:
            errors.append(_not_addressed(finding, excluded))

    cited = _cited_ids(items)
    if cited and details is not None:
        vulns = details.get("vulnerabilities")
        if vulns is None:
            errors.append(f"missing evidence: the vulnerabilities of {text} are unknown")
        else:
            own = {i for v in vulns for i in (v["id"], *v.get("aliases", []))}
            if shared := own & _expand(cited, ctx):
                errors.append(f"version {text} still has a cited vulnerability ({sorted(shared)})")
    return errors


def _check_pin(
    rec: Mapping[str, Any], ctx: ValidationContext, finding: str | None, items: list[Item]
) -> list[str]:
    bound = parse_bound(str(rec.get("target") or ""))
    if bound is None or bound[0] not in ("==", "<"):
        return [f"target: a pin needs a concrete '==V' or '<V' target, got {rec.get('target')!r}"]
    op, text = bound
    eligible, errors = _eligible_facts(ctx)
    if eligible is None:
        return errors
    allowed = _allowed(eligible)
    if op == "==":
        kept: str | None = text
        excluded = {v for v in allowed if v != Version(text)}
    else:
        kept = highest_allowed_below(eligible, text)
        excluded = {v for v in allowed if v >= Version(text)}
    if kept is None:
        errors.append(f"no currently allowed version is below {text}")
    else:
        errors += _version_facts(ctx, kept)[1]
    if finding == "spec_spans_major":
        errors.append(
            "a pin does not address 'spec_spans_major': spanning a major version alone is "
            "not sufficient"
        )
    elif finding is not None:
        supporting = [i for i in items if _supports(i, finding)]
        if not _in_excluded(finding, supporting, excluded):
            errors.append(_not_addressed(finding, excluded))
    return errors


def _check_replace(
    rec: Mapping[str, Any], ctx: ValidationContext, finding: str | None, eligible_findings: set[str]
) -> list[str]:
    errors: list[str] = []
    target = str(rec.get("target") or "").strip()
    kind = rec.get("replacement_type")
    assumptions = rec.get("suitability_assumptions")
    if not isinstance(assumptions, Sequence) or not any(
        isinstance(a, str) and a.strip() for a in assumptions
    ):
        errors.append("suitability_assumptions must not be empty for replace")

    if kind == "stdlib":
        if not _MODULE_NAME.match(target):
            errors.append(f"target: a stdlib replacement needs a module name, got {target!r}")
        elif target.split(".")[0] not in sys.stdlib_module_names:
            errors.append(f"{target!r} is not a stdlib module on Python 3.12")
    elif kind == "pypi":
        if not _PROJECT_NAME.match(target):
            errors.append(f"target: a replacement needs a PyPI project name, got {target!r}")
        else:
            errors += _check_candidate(target, ctx)
    else:
        errors.append(f"replacement_type must be 'pypi' or 'stdlib' for replace, got {kind!r}")

    if finding is not None and finding not in eligible_findings:
        errors.append(
            f"replace does not address finding {finding!r}: it must be a flag or a top-2 signal"
        )
    return errors


def _check_candidate(target: str, ctx: ValidationContext) -> list[str]:
    name = canonicalize_name(target)
    cand = _validation_output(
        ctx, "lookup_candidate", lambda a: canonicalize_name(str(a.get("name", ""))) == name
    )
    if cand is None or "error" in cand:
        return [f"missing evidence: replacement {target!r} was not looked up"]
    if not cand.get("exists"):
        return [f"replacement {target!r} does not exist on PyPI"]
    if not cand.get("valid"):
        return [f"replacement {target!r} cannot be placed as of T: {cand.get('reason')}"]
    errors = []
    if cand.get("effective_version") is None:
        errors.append(f"replacement {target!r} has no effective version on the target environment")
    original = ctx.profile.get("final_score")
    if original is None or cand.get("final_score") is None or cand["final_score"] >= original:
        errors.append(
            f"replacement score {cand.get('final_score')} is not lower than "
            f"{ctx.package}'s {original}"
        )
    if blockers := sorted(set(cand.get("flags", [])) & set(REPLACEMENT_BLOCKERS)):
        errors.append(f"replacement {target!r} has critical flags: {', '.join(blockers)}")
    return errors


def _check_do_nothing(
    ctx: ValidationContext, finding: str | None, top: list[str], items: list[Item]
) -> list[str]:
    errors: list[str] = []
    profile = ctx.profile
    if profile.get("effective_version") is None:
        errors.append("do_nothing is not allowed: the package has no effective version")
    elif profile.get("effective_version") == profile.get("reference_version") and (
        profile.get("evidence", {}).get("advisories")
        or (profile.get("signals", {}).get("S6", {}).get("value") or 0) > 0
    ):
        errors.append("do_nothing is not allowed: the effective version has advisories")
    if finding is not None and finding not in top:
        errors.append(
            f"do_nothing does not address finding {finding!r}: it must name a top-2 signal "
            f"({', '.join(top) or 'none'}) judged benign"
        )
    for s in top:
        if not any(_supports(i, s) for i in items):
            errors.append(f"do_nothing must cite evidence for every top-2 signal: none for {s}")
    return errors


# --- entry point ------------------------------------------------------------------------


def validate(rec: Mapping[str, Any], ctx: ValidationContext) -> list[str]:
    """Every §15 rule broken by ``rec``; an empty list means the facts check out."""
    action = rec.get("action")
    if action not in ACTIONS:
        return [f"action must be one of {', '.join(ACTIONS)}, got {action!r}"]
    if not ctx.profile:
        return ["missing evidence: no deterministic profile for the package"]

    errors: list[str] = []
    top = top_signals(ctx.profile)
    flags = {f["code"] for f in ctx.profile.get("flags", []) if isinstance(f.get("code"), str)}
    facts = {
        fact
        for c in ctx.calls
        if c.name == "get_requirement" and c.package == ctx.package
        for fact in S16_FACTS
        if c.output.get(fact) is True
    }
    raw_finding = rec.get("finding")
    finding: str | None = None  # set only when the finding exists
    if not isinstance(raw_finding, str) or not raw_finding.strip():
        errors.append("finding: exactly one finding is required")
    elif raw_finding not in flags | set(top) | facts:
        known_flags = ", ".join(sorted(flags)) or "none"
        errors.append(
            f"finding {raw_finding!r} does not exist: not a flag ({known_flags}), a top-2 "
            f"signal ({', '.join(top) or 'none'}) or a logged requirement-context fact"
        )
    else:
        finding = raw_finding

    items, evidence_errors = _check_evidence(rec.get("evidence"), ctx)
    errors += evidence_errors
    if finding is not None and items and not any(_supports(i, finding) for i in items):
        errors.append(f"no evidence item supports the finding {finding!r}")

    if action == "upgrade":
        errors += _check_upgrade(rec, ctx, finding, items)
    elif action == "pin":
        errors += _check_pin(rec, ctx, finding, items)
    elif action == "replace":
        errors += _check_replace(rec, ctx, finding, flags | set(top))
    else:
        errors += _check_do_nothing(ctx, finding, top, items)
    return errors

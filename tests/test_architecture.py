"""Import-boundary rules between the deprisk subpackages (PLAN.md "Dependency directions").

Every module is parsed with ``ast`` (nothing is imported), so the rules hold for code
paths that tests never execute.
"""

from __future__ import annotations

import ast
from pathlib import Path

from pydantic import BaseModel, ConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "deprisk"


class Import(BaseModel):
    model_config = ConfigDict(frozen=True)

    module: str  # importing module, e.g. "deprisk.risk.scoring"
    target: str  # imported module, e.g. "deprisk.data.models" or "httpx"
    top_level: bool  # False when the import sits inside a function (lazy import)


def _module_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve(module: str, is_package: bool, level: int, name: str | None) -> str:
    if level == 0:
        return name or ""
    base = module.split(".")
    if not is_package:
        base = base[:-1]
    base = base[: len(base) - (level - 1)]
    return ".".join([*base, name] if name else base)


def collect_imports(root: Path) -> list[Import]:
    found: list[Import] = []
    for path in sorted(root.rglob("*.py")):
        module = _module_name(path, root)
        is_package = path.name == "__init__.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        top_level_nodes = {id(node) for node in tree.body}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = _resolve(module, is_package, node.level, node.module)
                # "from deprisk.data import models" imports the submodule deprisk.data.models
                targets = [base] + [f"{base}.{alias.name}" for alias in node.names]
            else:
                continue
            for target in targets:
                found.append(
                    Import(module=module, target=target, top_level=id(node) in top_level_nodes)
                )
    return found


def _in(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".")


def _violations(root: Path = PACKAGE_ROOT) -> list[str]:
    errors: list[str] = []
    for imp in collect_imports(root):
        m, t = imp.module, imp.target

        def bad(reason: str, imp: Import = imp) -> None:
            errors.append(f"{imp.module} imports {imp.target}: {reason}")

        if m == "deprisk.config" and _in(t, "deprisk"):
            bad("config imports no deprisk module")
        if _in(t, "deprisk.pipeline") and m != "deprisk.cli":
            bad("only cli imports pipeline")
        if _in(t, "deprisk.cli") and m != "deprisk.__main__":
            bad("only __main__ imports cli")
        if _in(t, "anthropic") and m != "deprisk.agent.loop":
            bad("only agent.loop imports anthropic")
        if (
            m == "deprisk.pipeline"
            and imp.top_level
            and (_in(t, "deprisk.agent.loop") or _in(t, "anthropic"))
        ):
            bad("pipeline must import agent.loop lazily (--no-llm never loads anthropic)")

        if _in(m, "deprisk.data") and any(
            _in(t, p) for p in ("deprisk.risk", "deprisk.agent", "deprisk.reporting")
        ):
            bad("data imports no other subpackage")
        if _in(m, "deprisk.risk") and any(
            _in(t, p) for p in ("deprisk.agent", "deprisk.reporting", "httpx", "anthropic")
        ):
            bad("risk is pure: no agent, reporting, httpx or anthropic")
        if _in(m, "deprisk.agent") and _in(t, "deprisk.reporting"):
            bad("agent does not import reporting")
        if m == "deprisk.agent.validator" and any(
            _in(t, p) for p in ("httpx", "deprisk.data.pypi_client", "deprisk.agent.tools")
        ):
            bad("validator is pure: no network, no tools")
        if _in(m, "deprisk.reporting"):
            if _in(t, "httpx"):
                bad("reporting does no network IO")
            allowed = (
                "deprisk.config",
                "deprisk.data.models",
                "deprisk.risk.models",
                "deprisk.agent.models",
                "deprisk.reporting",
            )
            if (
                _in(t, "deprisk")
                and t not in ("deprisk", "deprisk.data", "deprisk.risk", "deprisk.agent")
                and not any(_in(t, p) for p in allowed)
            ):
                bad("reporting reads models only")
    return errors


def test_import_boundaries() -> None:
    assert _violations() == []


def test_scanner_detects_a_violation(tmp_path: Path) -> None:
    """Guard against a scanner that silently finds nothing."""
    fake_root = tmp_path / "deprisk"
    (fake_root / "risk").mkdir(parents=True)
    (fake_root / "risk" / "bad.py").write_text("import anthropic\n", encoding="utf-8")
    (fake_root / "pipeline.py").write_text("from deprisk.agent import loop\n", encoding="utf-8")
    errors = _violations(fake_root)
    assert any("risk is pure" in e for e in errors)
    assert any("lazily" in e for e in errors)

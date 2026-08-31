"""The scan engine.

Walks a tree, parses each supported file, and combines the three detectors into
findings. A finding requires all of:

    reachable by the model  AND  consequential  AND  no decision on the path

Never imports, executes, or evaluates the code being analysed -- `ast.parse`
builds a syntax tree and nothing more. That is what makes it safe to point this
scanner at a repository you do not trust.
"""

from __future__ import annotations

import ast
import fnmatch
import os

from .config import Config
from .detectors import decisions, reachability, sinks
from .model import Finding, ScanResult, UnsupportedFile

__all__ = ["scan_path", "scan_file", "scan_source", "SUPPORTED_SUFFIXES"]

#: Only Python is analysed. Anything else is reported as unsupported rather
#: than counted as clean.
SUPPORTED_SUFFIXES: tuple[str, ...] = (".py",)

#: Suffixes that look like source a user might expect to be covered. Reported
#: explicitly so a JavaScript agent does not silently scan as 0 findings.
NOTABLE_UNSUPPORTED: tuple[str, ...] = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rb", ".java")


def _signature_params(fn: ast.AST) -> list[str]:
    """Parameter names of a function, excluding self/cls.

    Covers positional-only, positional-or-keyword, keyword-only, *args and
    **kwargs. Reading only `args.args` (as an earlier prototype did) misses
    keyword-only parameters, which is exactly where an agent framework tends to
    put tool arguments.
    """
    args = getattr(fn, "args", None)
    if args is None:
        return []

    names: list[str] = []
    for arg in list(getattr(args, "posonlyargs", [])) + list(args.args):
        names.append(arg.arg)
    if args.vararg:
        names.append(f"*{args.vararg.arg}")
    for arg in args.kwonlyargs:
        names.append(arg.arg)
    if args.kwarg:
        names.append(f"**{args.kwarg.arg}")

    return [n for n in names if n not in ("self", "cls")]


def scan_source(source: str, path: str, config: Config | None = None) -> list[Finding]:
    """Analyse one module's source. Raises SyntaxError if it does not parse."""
    cfg = config or Config()
    tree = ast.parse(source, filename=path)

    action_map = reachability.declared_action_map(tree)
    hook = decisions.module_hook(tree)
    extra_decorators = frozenset(cfg.tool_decorators)
    extra_guards = frozenset(cfg.guards)
    module_functions = sinks.local_functions(tree)

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue

        route = reachability.reachability_of(node, action_map, extra_decorators)
        if not route:
            continue

        category, reason, confidence, sink_line, chain = sinks.classify_function(
            node, module_functions
        )
        if not category:
            continue

        evidence = decisions.decision_for(
            node,
            sink_line,
            hook,
            extra_guards,
            chain=chain,
            local_functions=module_functions,
        )

        findings.append(
            Finding(
                tool=node.name,
                file=path,
                line=node.lineno,
                category=category,
                reason=reason,
                reachable_by=route,
                inputs=_signature_params(node),
                evidence=evidence,
                confidence=confidence,
                action=action_map.get(node.name, ""),
            )
        )

    return findings


def scan_file(path: str, result: ScanResult, config: Config | None = None) -> None:
    """Analyse one file, appending to `result`."""
    try:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        result.unsupported.append(UnsupportedFile(path, f"unreadable: {exc.strerror}"))
        return
    except UnicodeDecodeError:
        result.unsupported.append(UnsupportedFile(path, "not valid UTF-8"))
        return

    try:
        findings = scan_source(source, path, config)
    except SyntaxError as exc:
        result.unsupported.append(UnsupportedFile(path, f"syntax error on line {exc.lineno}"))
        return
    except RecursionError:
        result.unsupported.append(UnsupportedFile(path, "expression too deeply nested to analyse"))
        return

    result.files += 1
    result.findings.extend(findings)

    try:
        if decisions.has_kiff_boundary(ast.parse(source, filename=path)):
            result.kiff_present = True
    except SyntaxError:  # pragma: no cover - already parsed once above
        pass


def _excluded(rel_path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(os.path.basename(rel_path), pat)
        for pat in patterns
    )


def scan_path(target: str, config: Config | None = None) -> ScanResult:
    """Analyse a file or directory tree."""
    cfg = config or Config()
    result = ScanResult()

    if os.path.isfile(target):
        if target.endswith(SUPPORTED_SUFFIXES):
            scan_file(target, result, cfg)
        else:
            result.unsupported.append(UnsupportedFile(target, "unsupported file type"))
        return result

    if not os.path.isdir(target):
        raise FileNotFoundError(target)

    exclude_dirs = cfg.all_exclude_dirs
    for root, dirs, files in os.walk(target):
        # Prune by path *segment*, not substring: matching "env" as a substring
        # would wrongly skip a directory named "environment_tools".
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".")]

        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, target)
            if _excluded(rel, cfg.exclude):
                continue
            if name.endswith(SUPPORTED_SUFFIXES):
                scan_file(full, result, cfg)
            elif name.endswith(NOTABLE_UNSUPPORTED):
                result.unsupported.append(
                    UnsupportedFile(full, "language not supported (Python only in v1)")
                )

    result.findings.sort(key=lambda f: (f.file, f.line))
    return result

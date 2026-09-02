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


def _functions_with_class_context(
    tree: ast.AST,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]]:
    """Every function in the module, paired with its tool base class if any.

    Collected in one traversal. A method's reachability depends on the class it
    is defined in -- `_run` is only a tool entry point on a Tool subclass --
    and that context is lost by a flat `ast.walk`.
    """
    out: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]] = []

    def visit(node: ast.AST, tool_base: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, reachability.is_tool_class(child))
            elif isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                out.append((child, tool_base))
                # Nested defs are helpers, not tool entry points, but they may
                # still contain classes; keep walking without the base.
                visit(child, "")
            else:
                visit(child, tool_base)

    visit(tree, "")
    return out


def scan_source(source: str, path: str, config: Config | None = None) -> list[Finding]:
    """Analyse one module's source. Raises SyntaxError if it does not parse."""
    cfg = config or Config()
    tree = ast.parse(source, filename=path)

    action_map = reachability.declared_action_map(tree)
    hook = decisions.module_hook(tree)
    extra_decorators = frozenset(cfg.tool_decorators)
    extra_guards = frozenset(cfg.guards)
    module_functions = sinks.local_functions(tree)
    imports = reachability.module_imports(tree)
    registered = reachability.registered_functions(tree)

    findings: list[Finding] = []
    for node, tool_base in _functions_with_class_context(tree):
        route = reachability.reachability_of(
            node,
            action_map,
            extra_decorators,
            imports=imports,
            registered=registered,
            tool_base=tool_base,
        )
        if not route:
            continue

        params = _signature_params(node)
        category, reason, confidence, sink_line, chain, sink_col = sinks.classify_function(
            node, module_functions, frozenset(params)
        )

        annotations = reachability.tool_annotations(node)

        # A tool that declares itself read-only and then calls something
        # destructive is the strongest finding available: the accusation comes
        # from the author's own metadata, not from the scanner's vocabulary.
        mismatch = bool(annotations.get("readOnlyHint")) and confidence == "call" and bool(category)

        # `destructiveHint=True` with nothing else found is still worth
        # surfacing: the author has told us it is dangerous.
        if not category and annotations.get("destructiveHint"):
            category, reason, confidence, sink_line, chain, sink_col = (
                "EXECUTION",
                "declares destructiveHint=True",
                "annotated",
                getattr(node, "end_lineno", node.lineno) + 1,
                [],
                0,
            )

        if not category:
            continue

        # A read-only annotation with no contradicting call is the author
        # telling us this is a read. Believe it.
        if annotations.get("readOnlyHint") and not mismatch:
            continue

        evidence = decisions.decision_for(
            node,
            sink_line,
            hook,
            extra_guards,
            chain=chain,
            local_functions=module_functions,
            approval=reachability.approval_evidence(node),
            sink_col=sink_col,
        )

        findings.append(
            Finding(
                tool=node.name,
                file=path,
                line=node.lineno,
                category=category,
                reason=reason,
                reachable_by=route,
                inputs=params,
                evidence=evidence,
                confidence=confidence,
                action=action_map.get(node.name, ""),
                annotation_mismatch=mismatch,
                annotations=annotations,
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

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

__all__ = ["scan_path", "scan_file", "scan_source", "is_test_code", "SUPPORTED_SUFFIXES"]

#: Only Python is analysed. Anything else is reported as unsupported rather
#: than counted as clean.
SUPPORTED_SUFFIXES: tuple[str, ...] = (".py",)

#: Suffixes that look like source a user might expect to be covered. Reported
#: explicitly so a JavaScript agent does not silently scan as 0 findings.
NOTABLE_UNSUPPORTED: tuple[str, ...] = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rb", ".java")


#: Tokens that must appear in a file's text for it to be able to produce a
#: finding. Every reachability route needs one of these somewhere: a decorator
#: name, a tool base class, a registration call, or an action map. The file is
#: still parsed either way -- an unparseable file must be reported as
#: unsupported rather than counted as clean -- but a module with none of these
#: skips the detector passes entirely.
_REGISTRATION_TOKENS: tuple[bytes, ...] = (
    b"tool",
    b"Tool",
    b"TOOL",
    b"task",
    b"action",
    b"ACTION",
    b"component",
    b"skill",
    b"kernel_function",
    b"bind(",
    b"GOVERNED",
    b"KIFF",
)


def _might_register_a_tool(source: str) -> bool:
    """Cheap text prefilter: could this file possibly expose a tool?"""
    data = source.encode("utf-8", errors="ignore")
    return any(token in data for token in _REGISTRATION_TOKENS)


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
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, str]]:
    """Every function in the module, with (tool base, enclosing class name).

    Collected in one traversal. A method's reachability depends on the class it
    is defined in -- `_run` is only a tool entry point on a Tool subclass --
    and that context is lost by a flat `ast.walk`. The class name is kept so a
    finding reads `ShellTool._run` rather than a bare `_run`.
    """
    out: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, str]] = []

    def visit(node: ast.AST, tool_base: str, class_name: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, reachability.is_tool_class(child), child.name)
            elif isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                out.append((child, tool_base, class_name))
                # Nested defs are helpers, not tool entry points, but they may
                # still contain classes; keep walking without the base.
                visit(child, "", "")
            else:
                visit(child, tool_base, class_name)

    visit(tree, "", "")
    return out


#: Path segments (relative to the scan root) that mark test, example and
#: documentation code. Findings there are real -- a `@tool` in a test file is
#: reachable by whatever agent the test builds -- but they are not the
#: product, so they are set aside rather than headlined.
TEST_CODE_SEGMENTS: frozenset[str] = frozenset(
    {
        "test",
        "tests",
        "testing",
        "fixtures",
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "cookbook",
        "cookbooks",
        "docs",
        "doc",
        "benchmark",
        "benchmarks",
    }
)


def is_test_code(rel_path: str) -> bool:
    """Whether `rel_path` (relative to the scan root) is test/example code.

    Judged on the path *below* the root only. Scanning `tests/fixtures/x.py`
    directly yields a relative path of `x.py`, which is product code as far as
    that scan is concerned -- the user pointed at it on purpose.
    """
    parts = rel_path.replace(os.sep, "/").split("/")
    name = parts[-1]
    if any(p in TEST_CODE_SEGMENTS for p in parts[:-1]):
        return True
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def scan_source(
    source: str,
    path: str,
    config: Config | None = None,
    tree: ast.AST | None = None,
) -> list[Finding]:
    """Analyse one module's source. Raises SyntaxError if it does not parse.

    An already-parsed `tree` may be passed in to avoid parsing twice.
    """
    cfg = config or Config()
    if tree is None:
        tree = ast.parse(source, filename=path)

    action_map = reachability.declared_action_map(tree)
    hook = decisions.module_hook(tree)
    extra_decorators = frozenset(cfg.tool_decorators)
    extra_guards = frozenset(cfg.guards)
    module_functions = sinks.local_functions(tree)
    imports = reachability.module_imports(tree)
    registered = reachability.registered_functions(tree)
    spec_names = reachability.tool_spec_names(tree)

    findings: list[Finding] = []
    for node, tool_base, class_name in _functions_with_class_context(tree):
        route = reachability.reachability_of(
            node,
            action_map,
            extra_decorators,
            imports=imports,
            registered=registered,
            tool_base=tool_base,
            spec_names=spec_names,
        )
        if not route:
            continue

        params = _signature_params(node)
        category, reason, confidence, sink_line, chain, sink_col, fixed = sinks.classify_function(
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
            category, reason, confidence, sink_line, chain, sink_col, fixed = (
                "EXECUTION",
                "declares destructiveHint=True",
                "annotated",
                getattr(node, "end_lineno", node.lineno) + 1,
                [],
                0,
                False,
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

        # A method on a tool class is named by its class: `ShellTool._run`
        # says something, `_run` says nothing.
        tool_name = node.name
        if class_name and route.endswith(f"({node.name})"):
            tool_name = f"{class_name}.{node.name}"

        findings.append(
            Finding(
                tool=tool_name,
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
                fixed_program=fixed,
            )
        )

    return findings


def scan_file(
    path: str, result: ScanResult, config: Config | None = None, rel_path: str | None = None
) -> None:
    """Analyse one file, appending to `result`.

    `rel_path` is the path relative to the scan root, used only to decide
    whether the file is test/example code. When absent the file is product
    code.
    """
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
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        result.unsupported.append(UnsupportedFile(path, f"syntax error on line {exc.lineno}"))
        return
    except RecursionError:
        result.unsupported.append(UnsupportedFile(path, "expression too deeply nested to analyse"))
        return

    # The file parsed, so it is analysable and counts. Whether the detectors
    # need to run is a separate question: a module with no tool-registration
    # token anywhere in its text cannot produce a finding, and in a real repo
    # most modules are like that.
    try:
        findings = (
            scan_source(source, path, config, tree=tree) if _might_register_a_tool(source) else []
        )
    except RecursionError:
        result.unsupported.append(UnsupportedFile(path, "expression too deeply nested to analyse"))
        return

    if rel_path is not None and is_test_code(rel_path):
        for f in findings:
            f.in_test_code = True

    result.files += 1
    result.findings.extend(findings)

    # Reuses the tree parsed above rather than parsing the file a second time.
    if decisions.has_kiff_boundary(tree):
        result.kiff_present = True


def _excluded(rel_path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(os.path.basename(rel_path), pat)
        for pat in patterns
    )


def scan_path(target: str, config: Config | None = None) -> ScanResult:
    """Analyse a file or directory tree."""
    cfg = config or Config()
    result = ScanResult(include_tests=cfg.include_tests)

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
                scan_file(full, result, cfg, rel_path=rel)
            elif name.endswith(NOTABLE_UNSUPPORTED):
                result.unsupported.append(
                    UnsupportedFile(full, "language not supported (Python only in v1)")
                )

    result.findings.sort(key=lambda f: (f.file, f.line))
    return result

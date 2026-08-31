"""Decisions: is there something on this path that can refuse the action?

This module is where the earlier prototype was unsound, so it is worth being
explicit about what changed.

The prototype computed one boolean per file:

    governed = any(signal in source_text for signal in SIGNALS)

Two defects. First, it is a substring match over raw text, so the word appearing
in a comment, a docstring, or an unrelated string literal counted as a guard.
Second and much worse, the verdict was file-wide: a module containing one
properly governed tool reported *every* tool in that module as governed,
including the completely unguarded ones. For a security scanner that is the
worst available failure mode, because it produces confident silence.

What this module does instead:

  - Works on the AST, so comments and unrelated strings cannot match.
  - Judges each sink individually, at function scope.
  - Requires lexical precedence: a guard call must appear *before* the sink to
    have gated it. A call afterwards is reported, not credited.
  - Keeps one honest whole-module signal -- a tool-hooks installation, which
    really does wrap every tool on an agent -- and labels it as such
    (`module_hook`) so a reader can see it is coarser than a per-call proof.

Vendor-neutral by default. A codebase's own `authorize()` clears a finding
exactly as a KIFF decision does; KIFF is one recognised answer, not the only
accepted one.
"""

from __future__ import annotations

import ast

from ..model import DecisionEvidence, Evidence

__all__ = [
    "GUARD_CALLS",
    "GUARD_DECORATORS",
    "KIFF_CALLS",
    "MODULE_HOOK_NAMES",
    "module_hook",
    "decision_for",
    "has_kiff_boundary",
]

#: KIFF's own decision boundary.
KIFF_CALLS: frozenset[str] = frozenset(
    {"decide", "kiff_decide", "cloud_decide", "propose", "require_decision"}
)

#: Vendor-neutral guard/authorization calls. A team using any of these is
#: already doing the thing; the scanner should not manufacture a finding to
#: advertise KIFF.
GUARD_CALLS: frozenset[str] = (
    frozenset(
        {
            "authorize",
            "authorize_action",
            "authorize_request",
            "check_permission",
            "check_access",
            "require_permission",
            "require_role",
            "require_auth",
            "require_approval",
            "has_permission",
            "has_role",
            "is_allowed",
            "can",
            "enforce",
            "verify_token",
            "verify_signature",
            "verify_api_key",
            "validate_jwt",
            "opa_eval",
            "casbin_enforce",
            "cedar_authorize",
            "confirm",
            "request_approval",
        }
    )
    | KIFF_CALLS
)

#: Decorators that gate the function they wrap.
GUARD_DECORATORS: frozenset[str] = frozenset(
    {
        "authorize",
        "authorized",
        "requires_permission",
        "require_permission",
        "requires_role",
        "require_role",
        "requires_auth",
        "require_auth",
        "login_required",
        "permission_required",
        "governed",
        "kiff_governed",
        "requires_approval",
        "require_approval",
    }
)

#: Constructor / keyword names whose presence at module level installs a guard
#: over every tool on an agent.
MODULE_HOOK_NAMES: frozenset[str] = frozenset({"KiffGuard", "Guard", "GuardHook", "ToolGuard"})

#: Keyword arguments that register such a hook.
MODULE_HOOK_KWARGS: frozenset[str] = frozenset({"tool_hooks", "hooks", "middleware"})


def _final_name(node: ast.expr) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def module_hook(tree: ast.AST) -> Evidence | None:
    """Detect a module-level guard installed over every tool.

    Recognised as either a guard constructor used as a hook, or a
    `tool_hooks=[...]` style keyword whose value mentions a guard.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for kw in node.keywords:
            if kw.arg not in MODULE_HOOK_KWARGS:
                continue
            for inner in ast.walk(kw.value):
                name = ""
                if isinstance(inner, ast.Call | ast.Name | ast.Attribute):
                    name = _final_name(inner)
                if name in MODULE_HOOK_NAMES:
                    return Evidence(
                        kind=DecisionEvidence.MODULE_HOOK,
                        detail=f"{name} installed via {kw.arg}= at module level",
                        line=getattr(node, "lineno", 0),
                    )
    return None


def _guard_decorator(fn: ast.AST) -> Evidence | None:
    for dec in getattr(fn, "decorator_list", []):
        name = _final_name(dec)
        if name in GUARD_DECORATORS:
            return Evidence(
                kind=DecisionEvidence.DECORATOR,
                detail=f"@{name} wraps the function",
                line=getattr(dec, "lineno", 0),
            )
    return None


def _guard_calls_in_body(fn: ast.AST, extra: frozenset[str]) -> list[tuple[int, str]]:
    """(line, name) for each recognised guard call in the function body."""
    recognised = GUARD_CALLS | extra
    found: list[tuple[int, str]] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _final_name(node)
            if name in recognised:
                found.append((node.lineno, name))
    return sorted(found)


def decision_for(
    fn: ast.AST,
    sink_line: int,
    hook: Evidence | None,
    extra_guards: frozenset[str] = frozenset(),
) -> Evidence:
    """Strongest decision evidence gating `sink_line` inside `fn`.

    Precedence: a guard decorator, then a guard call before the sink, then a
    module-wide hook, then a call after the sink (which does not gate it), then
    nothing.
    """
    decorator = _guard_decorator(fn)
    if decorator is not None:
        return decorator

    calls = _guard_calls_in_body(fn, extra_guards)
    before = [(line, name) for line, name in calls if line < sink_line]
    if before:
        line, name = before[-1]
        return Evidence(
            kind=DecisionEvidence.CALL_BEFORE_SINK,
            detail=f"{name}() before the sink",
            line=line,
        )

    if hook is not None:
        return hook

    if calls:
        line, name = calls[0]
        return Evidence(
            kind=DecisionEvidence.CALL_AFTER_SINK,
            detail=f"{name}() appears at line {line}, after the sink",
            line=line,
        )

    return Evidence(kind=DecisionEvidence.NONE, detail="none found on the analysed path")


def has_kiff_boundary(tree: ast.AST) -> bool:
    """Whether a KIFF decision boundary appears anywhere in this module."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _final_name(node) in KIFF_CALLS:
            return True
        if isinstance(node, ast.Name | ast.Attribute) and _final_name(node) in MODULE_HOOK_NAMES:
            return True
    return False

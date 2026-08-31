"""Reachability: is this function exposed to the model?

A consequential call inside a private helper that no agent can invoke is not
the same risk as one inside a registered tool. kiff-scan only reports functions
it can show are reachable by a model, which is the difference between a finding
and a lint.

Two recognised routes:

1. A tool decorator -- the function is registered as callable by the model.
2. A declared action mapping -- the codebase itself names the function as a
   governed action.

Route 2 is deliberately narrow. Accepting every dict literal whose values
happen to be uppercase strings (an earlier prototype did) turns any constant
table in the codebase into a tool registry and manufactures findings. Here a
mapping only counts when it is bound to a name that says it is one.
"""

from __future__ import annotations

import ast

__all__ = [
    "TOOL_DECORATORS",
    "ACTION_MAP_NAMES",
    "decorator_names",
    "declared_action_map",
    "reachability_of",
]

#: Decorator names that expose a function to a model. Matched on the final
#: attribute, so `@mcp.tool()`, `@agent.tool` and a bare `@tool` all match.
TOOL_DECORATORS: frozenset[str] = frozenset(
    {
        "tool",
        "tools",
        "function_tool",
        "agent_tool",
        "ai_function",
        "openai_function",
        "register_tool",
        "task",
        "component",
        "skill",
        "action",
    }
)

#: Variable names that mark a dict literal as a tool -> action mapping.
ACTION_MAP_NAMES: frozenset[str] = frozenset(
    {
        "TOOL_ACTION",
        "TOOL_ACTIONS",
        "ACTION_MAP",
        "ACTIONS",
        "TOOL_ACTION_MAP",
        "GOVERNED_ACTIONS",
        "KIFF_ACTIONS",
    }
)


def _final_name(node: ast.expr) -> str:
    """Final identifier of a decorator expression, or "" if not a name."""
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def decorator_names(fn: ast.AST) -> list[str]:
    """Decorator identifiers on a function, outermost first."""
    return [name for name in (_final_name(d) for d in getattr(fn, "decorator_list", [])) if name]


def _string_dict(node: ast.Dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        if (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            out[key.value] = value.value
    return out


def declared_action_map(tree: ast.AST) -> dict[str, str]:
    """Map tool name -> declared action name, from explicit declarations only.

    Recognised:
        TOOL_ACTION = {"drop_database": "DROP_DATABASE"}
        registry.bind("drop_database", action="DROP_DATABASE")
    """
    out: dict[str, str] = {}

    for node in ast.walk(tree):
        # A named mapping: only when the target name says it is an action map.
        if isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            if names & ACTION_MAP_NAMES and isinstance(node.value, ast.Dict):
                out.update(_string_dict(node.value))

        # An explicit binding call: registry.bind("tool", action="ACTION").
        if isinstance(node, ast.Call) and _final_name(node) == "bind":
            tool = ""
            if node.args and isinstance(node.args[0], ast.Constant):
                first = node.args[0].value
                tool = first if isinstance(first, str) else ""
            action = ""
            for kw in node.keywords:
                if kw.arg == "action" and isinstance(kw.value, ast.Constant):
                    val = kw.value.value
                    action = val if isinstance(val, str) else ""
            if tool and action:
                out[tool] = action

    return out


def reachability_of(
    fn: ast.AST,
    action_map: dict[str, str],
    extra_decorators: frozenset[str] = frozenset(),
) -> str:
    """Describe how a model reaches this function, or "" if it cannot.

    Returns a human-readable route such as "@tool" or "declared action", which
    is printed in the report. Reports must not claim `@tool` when the code
    actually used `@function_tool`.
    """
    recognised = TOOL_DECORATORS | extra_decorators
    for name in decorator_names(fn):
        if name in recognised:
            return f"@{name}"

    name = getattr(fn, "name", "")
    if name and name in action_map:
        return "declared action"

    return ""

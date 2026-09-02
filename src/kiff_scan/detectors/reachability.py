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
    "STRONG_TOOL_DECORATORS",
    "WEAK_TOOL_DECORATORS",
    "AGENT_FRAMEWORK_MODULES",
    "TOOL_BASE_SUFFIXES",
    "TOOL_METHODS",
    "APPROVAL_KWARGS",
    "ANNOTATION_HINTS",
    "ACTION_MAP_NAMES",
    "decorator_names",
    "declared_action_map",
    "reachability_of",
    "module_imports",
    "imports_agent_framework",
    "registered_functions",
    "tool_spec_names",
    "TOOL_SPEC_NAMES",
    "is_tool_class",
    "approval_evidence",
    "tool_annotations",
]

#: Decorator names that expose a function to a model on their own. Matched on
#: the final attribute, so `@mcp.tool()`, `@agent.tool` and a bare `@tool` all
#: match. Every name here means "tool" in some agent framework and means
#: nothing else in ordinary Python.
STRONG_TOOL_DECORATORS: frozenset[str] = frozenset(
    {
        "tool",
        "tools",
        "tool_plain",
        "function_tool",
        "agent_tool",
        "ai_function",
        "openai_function",
        "register_tool",
        "call_tool",
        "kernel_function",
        "mcp_tool",
        "toolkit",
    }
)

#: Decorator names that mean "unit of work" far more often than they mean
#: "model-callable tool". Every Celery beat schedule, Airflow DAG, Prefect flow
#: and Django admin action uses one, so on their own they turn a backend repo
#: with no LLM in it into an agent with a blast radius. They only count when
#: the module also imports an agent framework.
WEAK_TOOL_DECORATORS: frozenset[str] = frozenset({"task", "action", "component", "skill", "step"})

#: Modules whose presence in a file's imports makes a weak decorator credible.
AGENT_FRAMEWORK_MODULES: frozenset[str] = frozenset(
    {
        "langchain",
        "langchain_core",
        "langchain_community",
        "langgraph",
        "crewai",
        "agno",
        "phi",
        "strands",
        "pydantic_ai",
        "openai",
        "agents",
        "mcp",
        "fastmcp",
        "smolagents",
        "autogen",
        "autogen_agentchat",
        "llama_index",
        "haystack",
        "semantic_kernel",
        "google",
        "anthropic",
        "litellm",
        "instructor",
    }
)

#: Base-class name suffixes that mark a class as an agent tool. LangChain and
#: CrewAI tools are classes, not decorated functions, and their action lives in
#: `_run`. Decorator-only reachability misses all of them.
TOOL_BASE_SUFFIXES: tuple[str, ...] = ("Tool", "BaseTool", "Toolkit", "ToolSpec")

#: Methods on such a class that the framework invokes with model-controlled
#: arguments.
TOOL_METHODS: frozenset[str] = frozenset({"_run", "_arun", "run", "execute", "__call__", "call"})

#: Callables that register a plain function as a tool: `StructuredTool.
#: from_function(fn)`, `Tool(func=fn)`, `FunctionTool(fn)`.
REGISTRATION_CALLS: frozenset[str] = frozenset(
    {
        "from_function",
        "from_defaults",
        "Tool",
        "StructuredTool",
        "FunctionTool",
        "BaseTool",
        "tool",
    }
)

#: Keyword arguments on a tool decorator that declare a human-in-the-loop
#: boundary. These are decision boundaries expressed in the framework's own
#: vocabulary, and treating them as ungoverned is how a scanner reports an
#: entire `human_in_the_loop/` example folder as unguarded.
APPROVAL_KWARGS: frozenset[str] = frozenset(
    {
        "requires_confirmation",
        "requires_user_input",
        "needs_approval",
        "require_approval",
        "confirm",
        "human_in_the_loop",
        "requires_human_approval",
        # agno: the agent pauses and hands execution to the developer's code
        # rather than running the tool itself. That is a boundary, expressed
        # as control transfer rather than as a confirmation prompt.
        "external_execution",
    }
)

#: MCP ToolAnnotations fields that state what the tool does to the world.
ANNOTATION_HINTS: frozenset[str] = frozenset(
    {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
)

#: Retained for compatibility: the union is what a caller asking "is this a
#: tool decorator?" historically meant.
TOOL_DECORATORS: frozenset[str] = STRONG_TOOL_DECORATORS | WEAK_TOOL_DECORATORS

#: Module-level dicts that declare the module's own tool. Strands uses
#: `TOOL_SPEC = {"name": "python_repl", ...}` alongside a module-level function
#: of that name, and 20 of its 47 tool modules are written this way -- a whole
#: framework's registration shape, invisible to decorator-only reachability.
TOOL_SPEC_NAMES: frozenset[str] = frozenset({"TOOL_SPEC", "TOOLSPEC", "SPEC", "TOOL_DEFINITION"})

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


def module_imports(tree: ast.AST) -> frozenset[str]:
    """Top-level package names imported by this module."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".")[0])
    return frozenset(out)


def imports_agent_framework(imports: frozenset[str]) -> bool:
    """Whether this module imports something that makes an agent."""
    return bool(imports & AGENT_FRAMEWORK_MODULES)


def _name_of(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def registered_functions(tree: ast.AST) -> dict[str, str]:
    """Functions registered as tools by a call rather than a decorator.

    Recognises the shapes that carry most production tools:

        StructuredTool.from_function(wipe)
        Tool(name="x", func=terminate)
        FunctionTool(handler)
        self.mcp.tool(name="manage")(self.manage)

    Returns {function_name: how_it_was_registered}.
    """
    out: dict[str, str] = {}

    def note(node: ast.expr, how: str) -> None:
        target = node
        if isinstance(target, ast.Attribute):
            out.setdefault(target.attr, how)
        elif isinstance(target, ast.Name):
            out.setdefault(target.id, how)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _name_of(node.func)

        # `X.tool(...)(fn)` -- the outer call's func is itself a tool call.
        if isinstance(node.func, ast.Call) and _name_of(node.func.func) in STRONG_TOOL_DECORATORS:
            for arg in node.args:
                note(arg, f"{_name_of(node.func.func)}(...)(fn) registration")
            continue

        if callee not in REGISTRATION_CALLS:
            continue

        for arg in node.args:
            if isinstance(arg, ast.Name | ast.Attribute):
                note(arg, f"registered via {callee}()")
        for kw in node.keywords:
            if kw.arg in ("func", "fn", "function", "coroutine") and isinstance(
                kw.value, ast.Name | ast.Attribute
            ):
                note(kw.value, f"registered via {callee}({kw.arg}=)")

    return out


def tool_spec_names(tree: ast.AST) -> frozenset[str]:
    """Function names declared by a module-level tool spec.

    Deliberately narrow: the assignment target has to be a recognised spec
    name and the dict has to carry a string `name`. A dict literal that merely
    has a "name" key is not evidence of anything.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        if not (targets & TOOL_SPEC_NAMES) or not isinstance(node.value, ast.Dict):
            continue
        for key, value in zip(node.value.keys, node.value.values, strict=False):
            if (
                isinstance(key, ast.Constant)
                and key.value == "name"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                out.add(value.value)
    return frozenset(out)


def is_tool_class(cls: ast.ClassDef) -> str:
    """The tool base this class derives from, or "" if it is not a tool.

    Matched on the base *name* rather than a resolved import, because the
    import path varies by framework while the name does not.
    """
    for base in cls.bases:
        name = _name_of(base)
        if name and any(name.endswith(suffix) for suffix in TOOL_BASE_SUFFIXES):
            return name
    return ""


def _decorator_kwargs(fn: ast.AST) -> list[tuple[str, ast.expr, int]]:
    """(keyword, value, line) for every kwarg on every decorator call."""
    out: list[tuple[str, ast.expr, int]] = []
    for dec in getattr(fn, "decorator_list", []):
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg:
                    out.append((kw.arg, kw.value, getattr(dec, "lineno", 0)))
    return out


def approval_evidence(fn: ast.AST) -> tuple[str, int] | None:
    """A framework-native approval flag on the tool decorator, if any.

    Only a literal `True` counts. `requires_confirmation=False` is the author
    saying the opposite, and `requires_confirmation=some_flag` is unknowable
    statically, so neither clears the finding.
    """
    for name, value, line in _decorator_kwargs(fn):
        if name not in APPROVAL_KWARGS:
            continue
        if isinstance(value, ast.Constant) and value.value is True:
            return f"{name}=True on the tool decorator", line
    return None


def tool_annotations(fn: ast.AST) -> dict[str, bool]:
    """MCP ToolAnnotations declared on the tool decorator.

    `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))` is the tool
    author stating what their tool does to the world. It is the only place in
    the ecosystem where that claim is machine-readable, which makes it both
    good evidence and -- when it contradicts the body -- the most convincing
    finding this scanner can print.
    """
    out: dict[str, bool] = {}
    for name, value, _line in _decorator_kwargs(fn):
        candidates: list[ast.Call] = []
        if name == "annotations" and isinstance(value, ast.Call):
            candidates.append(value)
        elif name in ANNOTATION_HINTS and isinstance(value, ast.Constant):
            if isinstance(value.value, bool):
                out[name] = value.value
        for call in candidates:
            for kw in call.keywords:
                if (
                    kw.arg in ANNOTATION_HINTS
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, bool)
                ):
                    out[kw.arg] = kw.value.value
    return out


def reachability_of(
    fn: ast.AST,
    action_map: dict[str, str],
    extra_decorators: frozenset[str] = frozenset(),
    *,
    imports: frozenset[str] = frozenset(),
    registered: dict[str, str] | None = None,
    tool_base: str = "",
    spec_names: frozenset[str] = frozenset(),
) -> str:
    """Describe how a model reaches this function, or "" if it cannot.

    Returns a human-readable route such as "@tool" or "BaseTool subclass",
    which is printed verbatim in the report. Reports must not claim `@tool`
    when the code actually used `@function_tool`.
    """
    strong = STRONG_TOOL_DECORATORS | extra_decorators
    names = decorator_names(fn)

    for name in names:
        if name in strong:
            return f"@{name}"

    # A method on a class that derives from a tool base is invoked by the
    # framework with model-controlled arguments.
    fn_name = getattr(fn, "name", "")
    if tool_base and fn_name in TOOL_METHODS:
        return f"{tool_base} subclass ({fn_name})"

    if registered and fn_name in registered:
        return registered[fn_name]

    if fn_name and fn_name in spec_names:
        return "TOOL_SPEC declaration"

    # Weak decorators only count alongside an agent framework import. Without
    # one, `@app.task` is a Celery job and this is a backend repo.
    for name in names:
        if name in WEAK_TOOL_DECORATORS and imports_agent_framework(imports):
            return f"@{name}"

    if fn_name and fn_name in action_map:
        return "declared action"

    return ""

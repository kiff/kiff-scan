"""Sinks: what consequential thing does this function actually do?

Two levels of proof, and the distinction is reported rather than blurred:

  "call"     -- an actual SDK call was found in the function body. Strong.
  "declared" -- the body is a placeholder or a wrapper and the classification
                comes from the function's name and docstring. Weaker, so it is
                capped below "high" severity and can never on its own fail a
                build at the default threshold.

Keeping the weaker signal is deliberate: agent tool bodies are very often thin
shims that delegate to a service, and dropping them would report clean on an
agent that can plainly drop a database. Silently treating it as equally certain
would be dishonest, so it is labelled instead.
"""

from __future__ import annotations

import ast
import re

__all__ = [
    "SINK_CALLS",
    "SHELL_ARGV",
    "EXEC_CALLS",
    "NAME_HINTS",
    "READ_ONLY_PREFIXES",
    "INFORMATIONAL_TOKENS",
    "GATED_SINK_CALLS",
    "EXEC_METHODS",
    "EXEC_RECEIVERS",
    "OS_EXEC_CALLS",
    "CODE_EXEC_BUILTINS",
    "MAX_CALL_DEPTH",
    "INTERPRETERS",
    "tokenize_identifier",
    "classify_function",
    "local_functions",
    "guard_calls_in_chain",
]

#: Final attribute of a call -> consequence category. Matched on the method
#: name so that `client.delete_db_instance(...)`, `rds.delete_db_instance(...)`
#: and a bare import all resolve identically.
SINK_CALLS: dict[str, str] = {
    # Stored data
    "delete_db_instance": "DATA_LOSS",
    "delete_db_cluster": "DATA_LOSS",
    "drop_database": "DATA_LOSS",
    "drop_table": "DATA_LOSS",
    "delete_table": "DATA_LOSS",
    "delete_objects": "DATA_LOSS",
    "delete_bucket": "DATA_LOSS",
    "delete_collection": "DATA_LOSS",
    "flushall": "DATA_LOSS",
    "flushdb": "DATA_LOSS",
    # Compute
    "terminate_instances": "COMPUTE",
    "delete_cluster": "COMPUTE",
    "delete_nodegroup": "COMPUTE",
    "delete_namespace": "COMPUTE",
    "delete_deployment": "COMPUTE",
    "stop_instances": "COMPUTE",
    # Identity and secrets
    "rotate_secret": "IDENTITY",
    "delete_secret": "IDENTITY",
    "put_secret_value": "IDENTITY",
    "create_access_key": "IDENTITY",
    "delete_access_key": "IDENTITY",
    "put_user_policy": "IDENTITY",
    "attach_role_policy": "IDENTITY",
    "attach_user_policy": "IDENTITY",
    "add_user_to_group": "IDENTITY",
    # Traffic
    "change_resource_record_sets": "NETWORK",
    "modify_listener": "NETWORK",
    "set_traffic_split": "NETWORK",
    # Money
    "create_refund": "MONEY",
    "create_payout": "MONEY",
    "create_transfer": "MONEY",
    "cancel_subscription": "MONEY",
    # Schema
    "execute_ddl": "DATABASE",
    "run_migration": "DATABASE",
}

#: Sinks whose method name is too common to stand alone. `capture` is rich's
#: output helper before it is a payment capture; `upgrade` is Alembic's before
#: it is anything; `update_service` is generic. Each needs corroboration from
#: the receiver or from a parameter name before it counts.
GATED_SINK_CALLS: dict[str, tuple[str, frozenset[str], frozenset[str]]] = {
    # name: (category, receiver roots, parameter/keyword names)
    "capture": (
        "MONEY",
        frozenset({"stripe", "braintree", "paypal", "adyen", "charge", "payment_intent", "intent"}),
        frozenset({"amount", "charge", "payment_intent", "currency"}),
    ),
    "refund": (
        "MONEY",
        frozenset({"stripe", "braintree", "paypal", "adyen", "charge", "payment", "order"}),
        frozenset({"amount", "charge", "payment_intent", "order_id", "currency"}),
    ),
    "upgrade": ("DATABASE", frozenset({"alembic", "command", "op"}), frozenset({"revision"})),
    "downgrade": ("DATABASE", frozenset({"alembic", "command", "op"}), frozenset({"revision"})),
    "update_service": (
        "NETWORK",
        frozenset({"ecs", "client", "boto3"}),
        frozenset({"cluster", "service", "taskDefinition", "desiredCount"}),
    ),
}

#: First shell token -> category, for a subprocess-style call.
SHELL_ARGV: dict[str, str] = {
    "kubectl": "DEPLOYMENT",
    "helm": "DEPLOYMENT",
    "terraform": "DEPLOYMENT",
    "pulumi": "DEPLOYMENT",
    "argocd": "DEPLOYMENT",
    "psql": "DATABASE",
    "mysql": "DATABASE",
    "mongo": "DATABASE",
    "alembic": "DATABASE",
    "migrate": "DATABASE",
    "aws": "IDENTITY",
    "gcloud": "IDENTITY",
    "rm": "DATA_LOSS",
}

#: Programs whose arguments are themselves commands or code. Handing one of
#: these a model-controlled argument is arbitrary execution. Any *other*
#: constant argv[0] -- `say`, `git`, `ffmpeg` -- is a fixed program whose
#: arguments the model controls: still execution reachability, but not the
#: same claim, and reported at low severity rather than as a shell.
INTERPRETERS: frozenset[str] = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "fish",
        "ksh",
        "csh",
        "tcsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "pwsh",
        "python",
        "python3",
        "python2",
        "node",
        "ruby",
        "perl",
        "php",
        "lua",
        "Rscript",
        "osascript",
        "ssh",
        "sudo",
        "su",
        "doas",
        "env",
        "xargs",
        "eval",
        "exec",
        "docker",
        "podman",
        "nsenter",
        "chroot",
        "crontab",
        "at",
        "nohup",
        "setsid",
    }
)

#: Method names that hand a command to the operating system *when the receiver
#: is an execution API*. `run` and `call` are the two most common method names
#: in every agent framework -- `agent.run()`, `chain.run()`, `client.call()` --
#: so matching them on name alone reports innocent delegation as shell
#: execution. The receiver is what distinguishes `subprocess.run` from
#: `agent.run`, so it is required.
EXEC_METHODS: frozenset[str] = frozenset(
    {
        "run",
        "call",
        "Popen",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "system",
        "popen",
        "spawn",
        "spawnl",
        "spawnv",
        "exec_command",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "forkpty",
        "posix_spawn",
        "posix_spawnp",
    }
)

#: Receiver roots that make the above an execution call. Matched on the root of
#: the dotted path (`subprocess.run` -> "subprocess", `asyncio.subprocess.x` ->
#: "asyncio"), and additionally on the immediate attribute so
#: `self.pexpect.spawn` still resolves.
EXEC_RECEIVERS: frozenset[str] = frozenset(
    {"subprocess", "os", "asyncio", "pexpect", "pty", "commands", "sh", "delegator"}
)

#: Paramiko-style remote execution: the receiver is a session object whose name
#: is not statically knowable, so the method name alone carries it.
EXEC_METHODS_ANY_RECEIVER: frozenset[str] = frozenset({"exec_command"})

#: The `os.exec*` family and friends. Matched on the attribute name with an
#: `os` receiver, or bare when imported directly.
OS_EXEC_CALLS: frozenset[str] = frozenset(
    {
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "posix_spawn",
        "posix_spawnp",
    }
)

#: Builtins that execute source text. Only ever matched as a bare `Name` call:
#: an arbitrary object's `.exec()` method is not the Python builtin, and
#: `cursor.execute()` is a database call, not this.
CODE_EXEC_BUILTINS: frozenset[str] = frozenset({"exec", "eval"})

#: Kept for backwards compatibility with anything importing the old name.
EXEC_CALLS: frozenset[str] = EXEC_METHODS | OS_EXEC_CALLS | CODE_EXEC_BUILTINS

#: Ordered name keywords -> category. Matched against whole *tokens* of the
#: identifier, never as substrings: "drop" is a token of `drop_database` and is
#: not a token of `select_dropdown`. Order matters; the first match wins.
NAME_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("drop", "purge", "truncate", "wipe", "destroy"), "DATA_LOSS"),
    (("terminate", "teardown", "decommission"), "COMPUTE"),
    (("rollback", "deploy", "redeploy", "restart", "scale"), "DEPLOYMENT"),
    (("failover", "reroute", "cutover", "traffic"), "NETWORK"),
    (("rotate", "revoke"), "IDENTITY"),
    (("migration", "migrate"), "DATABASE"),
    (("refund", "payout", "chargeback", "disburse"), "MONEY"),
)

#: Name prefixes that describe a read. A function called `get_*`/`list_*` is
#: asserting it does not change anything; that assertion outranks a keyword
#: appearing incidentally elsewhere in its name or docs. This vetoes only
#: *declared* confidence -- an observed destructive call in the body still
#: reports, because a read-only name in front of `delete_table()` is a lie the
#: scanner should surface rather than believe.
READ_ONLY_PREFIXES: frozenset[str] = frozenset(
    {
        "get",
        "list",
        "describe",
        "read",
        "search",
        "lookup",
        "preview",
        "validate",
        "check",
        "analyze",
        "analyse",
        "show",
        "fetch",
        "query",
        "inspect",
        "count",
        "find",
        "view",
        "render",
        "format",
        "parse",
        "select",
    }
)


#: Tokens that mark a tool as informational wherever they appear in the name.
#: `deploy_serverless_app_help_tool` describes deployment; it does not deploy.
#: Unlike the prefix veto these are checked anywhere in the identifier, because
#: the giveaway word is usually at the end.
INFORMATIONAL_TOKENS: frozenset[str] = frozenset(
    {
        "help",
        "doc",
        "docs",
        "documentation",
        "guide",
        "guidance",
        "guideline",
        "example",
        "examples",
        "tutorial",
        "reference",
        "info",
        "status",
        "readme",
        "usage",
        "explain",
        "summary",
        "recommend",
        "recommendation",
        "advice",
    }
)


#: How many leading words of a docstring summary may carry the declared verb.
SUMMARY_VERB_WINDOW = 4


def tokenize_identifier(name: str) -> list[str]:
    """Semantic tokens of an identifier: snake_case and CamelCase both split.

    `drop_database` -> ["drop", "database"];  `select_dropdown` -> ["select",
    "dropdown"];  `rotateSecretKey` -> ["rotate", "secret", "key"]. This is the
    difference between matching a word and matching a substring.
    """
    parts = re.split(r"[_\W]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", name)
    return [p.lower() for p in parts if p]


def _first_sentence(doc: str) -> str:
    """The docstring's first sentence, which is where the summary lives.

    Explanatory prose further down mentions "credentials", "truncated" and
    "scale" for entirely innocent reasons, and crediting it produced most of
    the audit's false positives.
    """
    text = (doc or "").strip()
    if not text:
        return ""
    head = text.split("\n\n", 1)[0].replace("\n", " ")
    for stop in (". ", "! ", "? "):
        idx = head.find(stop)
        if idx != -1:
            head = head[: idx + 1]
            break
    return head


def _final_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _argv_literal(fn: ast.AST | None, name: str) -> ast.List | ast.Tuple | None:
    """The list literal a local `cmd = [...]` variable was assigned, if unique.

    `cmd = ["rg", "--files", path]; subprocess.run(cmd)` is the common way to
    build an argv, and without resolving it the program is unknown and the
    call is reported as a shell. One unambiguous assignment in the same
    function is resolved; anything else stays unknown.
    """
    if fn is None:
        return None
    found: list[ast.List | ast.Tuple] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.List | ast.Tuple):
            if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                found.append(node.value)
        elif (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return None  # extended later: be conservative and treat as unknown
    return found[0] if len(found) == 1 else None


def _shell_token(call: ast.Call, fn: ast.AST | None = None) -> str:
    """First shell token of a subprocess-style call, if statically known."""
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            parts = arg.value.strip().split()
            return parts[0] if parts else ""
        if isinstance(arg, ast.Name):
            arg = _argv_literal(fn, arg.id)
            if arg is None:
                return ""
        if isinstance(arg, ast.List | ast.Tuple) and arg.elts:
            first = arg.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        break
    return ""


def _receiver_parts(call: ast.Call) -> list[str]:
    """Dotted receiver path of a call, outermost last.

    `subprocess.run(...)` -> ["subprocess"];  `asyncio.create_subprocess_shell`
    -> ["asyncio"];  `self.mcp.tool(...)` -> ["self", "mcp"]. Empty for a bare
    `Name` call.
    """
    func = call.func
    if not isinstance(func, ast.Attribute):
        return []
    parts: list[str] = []
    node: ast.expr = func.value
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_final_name(node))
    return [p for p in reversed(parts) if p]


def _is_bare_name_call(call: ast.Call, name: str) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == name


def _kwarg_names(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg}


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _exec_sink(call: ast.Call, name: str) -> tuple[str, str] | None:
    """Whether this call hands something to the OS or to a code evaluator.

    Receiver-aware on purpose: the whole point is that `subprocess.run` is
    execution and `agent.run` is not.
    """
    receivers = _receiver_parts(call)
    root = receivers[0] if receivers else ""
    last = receivers[-1] if receivers else ""

    # exec()/eval() as builtins only. `obj.exec()` is somebody's method and
    # `cursor.execute()` is a database call.
    if name in CODE_EXEC_BUILTINS and _is_bare_name_call(call, name):
        return "EXECUTION", f"evaluates code via {name}()"

    # os.execvp(...) and friends, or a direct `from os import execvp`.
    if name in OS_EXEC_CALLS and (root in {"os", "posix"} or not receivers):
        return "EXECUTION", f"replaces the process via {name}()"

    if name in EXEC_METHODS:
        if root in EXEC_RECEIVERS or last in EXEC_RECEIVERS:
            return "EXECUTION", f"shell/exec via {'.'.join([*receivers, name])}()"
        if name in EXEC_METHODS_ANY_RECEIVER:
            return "EXECUTION", f"remote command via {name}()"
        if _has_shell_true(call):
            return "EXECUTION", f"shell/exec via {name}(shell=True)"

    return None


def _gated_sink(call: ast.Call, name: str, params: frozenset[str]) -> tuple[str, str] | None:
    """A common-word sink that needs corroboration before it counts."""
    entry = GATED_SINK_CALLS.get(name)
    if entry is None:
        return None
    category, receivers, hints = entry
    parts = {p.lower() for p in _receiver_parts(call)}
    if parts & receivers:
        return category, f"calls {name}() on {sorted(parts & receivers)[0]}"
    corroborating = (_kwarg_names(call) | params) & hints
    if corroborating:
        return category, f"calls {name}() with {sorted(corroborating)[0]}"
    return None


def _is_fixed_program(call: ast.Call, token: str, fn: ast.AST | None = None) -> bool:
    """A constant argv[0] that is not an interpreter, with no `shell=True`.

    `subprocess.run(["say", text])` lets the model choose what is said, not
    what runs. That is a real capability and it is reported -- but as a fixed
    program with model-controlled arguments, not as a shell.
    """
    if not token or _has_shell_true(call):
        return False
    base = token.rsplit("/", 1)[-1]
    if token in INTERPRETERS or base in INTERPRETERS or base in SHELL_ARGV:
        return False
    # A bare string command ("say hello") is parsed by a shell only with
    # shell=True; as an argv list the program is the literal first element.
    first = call.args[0] if call.args else None
    if isinstance(first, ast.Name):
        first = _argv_literal(fn, first.id)
    return isinstance(first, ast.List | ast.Tuple)


def _sink_from_body(
    fn: ast.AST, params: frozenset[str] = frozenset()
) -> tuple[str, str, int, int, bool]:
    """First recognised sink call: (category, reason, line, col, fixed_program).

    Line 0 if none. `fixed_program` is True when the execution sink runs a
    constant, non-interpreter program whose arguments the model controls.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _final_name(node)

        if name in SINK_CALLS:
            return SINK_CALLS[name], f"calls {name}()", node.lineno, node.col_offset, False

        gated = _gated_sink(node, name, params)
        if gated is not None:
            return gated[0], gated[1], node.lineno, node.col_offset, False

        execed = _exec_sink(node, name)
        if execed is not None:
            token = _shell_token(node, fn)
            if token in SHELL_ARGV:
                return (
                    SHELL_ARGV[token],
                    f"shells out to {token}",
                    node.lineno,
                    node.col_offset,
                    False,
                )
            if _is_fixed_program(node, token, fn):
                return (
                    execed[0],
                    f"runs the fixed program {token} with model-controlled arguments",
                    node.lineno,
                    node.col_offset,
                    True,
                )
            if token:
                return (
                    execed[0],
                    f"{execed[1]} running {token}",
                    node.lineno,
                    node.col_offset,
                    False,
                )
            return execed[0], execed[1], node.lineno, node.col_offset, False

    return "", "", 0, 0, False


def _sink_from_name(name: str, doc: str) -> tuple[str, str]:
    """Classify from the declaration alone, on whole tokens.

    The function name is the stronger signal and is checked first. Only if it
    says nothing is the docstring's *first sentence* consulted, and a read-only
    name prefix vetoes the whole inference: `read_documentation` is not data
    loss because its summary happens to mention truncation.
    """
    name_tokens = tokenize_identifier(name)
    if name_tokens and name_tokens[0] in READ_ONLY_PREFIXES:
        return "", ""
    if set(name_tokens) & INFORMATIONAL_TOKENS:
        return "", ""

    token_set = set(name_tokens)
    for keywords, category in NAME_HINTS:
        for keyword in keywords:
            if keyword in token_set:
                return category, f"declared action ({keyword} in the name)"

    # A tool summary is imperative: "Deploy the release", "Drop a search
    # index". The verb sits at the front. A keyword deep in the sentence --
    # "Start here if a user wants to run locally or deploy to the cloud" --
    # is describing context, not declaring the action, and crediting it is
    # how a containerisation helper became a deployment finding.
    doc_tokens: list[str] = []
    for word in re.split(r"[^A-Za-z0-9_]+", _first_sentence(doc)):
        doc_tokens.extend(tokenize_identifier(word))
    leading = set(doc_tokens[:SUMMARY_VERB_WINDOW])
    for keywords, category in NAME_HINTS:
        for keyword in keywords:
            if keyword in leading:
                return category, f"declared action ({keyword} in the summary)"

    return "", ""


#: How many module-local calls deep to follow. Agent tools are commonly thin
#: wrappers over a helper, so stopping at the tool body reports clean on an agent
#: that can plainly drop a database. Bounded to keep analysis fast and
#: terminating; cycles are cut by the `seen` set.
MAX_CALL_DEPTH = 4


def local_functions(tree: ast.AST) -> dict[str, ast.AST]:
    """Map name -> definition for every function defined in this module."""
    out: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            out.setdefault(node.name, node)
    return out


def _sink_via_local_calls(
    fn: ast.AST,
    locals_: dict[str, ast.AST],
    depth: int,
    seen: frozenset[str],
    params: frozenset[str] = frozenset(),
) -> tuple[str, str, int, list[str], bool]:
    """Follow calls to module-local functions looking for a sink.

    Returns (category, reason, line_in_this_function, chain). `line_in_this_
    function` is the line of the *call* that leads to the sink, so lexical
    precedence in the caller stays meaningful: a guard placed before the helper
    call does gate it.
    """
    if depth <= 0:
        return "", "", 0, [], False

    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _final_name(node)
        if name not in locals_ or name in seen:
            continue

        callee = locals_[name]

        category, reason, _line, _col, fixed = _sink_from_body(callee, params)
        if category:
            return category, f"calls {name}() which {reason}", node.lineno, [name], fixed

        category, reason, _line, chain, fixed = _sink_via_local_calls(
            callee, locals_, depth - 1, seen | {name}, params
        )
        if category:
            return category, f"calls {name}() which {reason}", node.lineno, [name, *chain], fixed

    return "", "", 0, [], False


def guard_calls_in_chain(
    fn: ast.AST,
    locals_: dict[str, ast.AST],
    chain: list[str],
    recognised: frozenset[str],
) -> tuple[int, str] | None:
    """A recognised guard call inside the called helper chain, if any.

    Without this, moving a guard into the same helper that performs the action
    would turn a correctly-guarded tool into a false positive.
    """
    for name in chain:
        callee = locals_.get(name)
        if callee is None:
            continue
        for node in ast.walk(callee):
            if isinstance(node, ast.Call) and _final_name(node) in recognised:
                return node.lineno, f"{_final_name(node)}() inside {name}()"
    return None


def classify_function(
    fn: ast.AST,
    locals_: dict[str, ast.AST] | None = None,
    params: frozenset[str] = frozenset(),
) -> tuple[str, str, str, int, list[str], int, bool]:
    """Classify a function's consequence.

    Returns (category, reason, confidence, sink_line, chain, sink_col,
    fixed_program). Category is "" when the function is not a recognised
    consequential action. `chain` names the module-local helpers traversed to
    reach the sink, empty for a direct call. `fixed_program` marks an execution
    sink whose argv[0] is a constant non-interpreter.
    """
    category, reason, line, col, fixed = _sink_from_body(fn, params)
    if category:
        return category, reason, "call", line, [], col, fixed

    if locals_:
        category, reason, line, chain, fixed = _sink_via_local_calls(
            fn, locals_, MAX_CALL_DEPTH, frozenset({getattr(fn, "name", "")}), params
        )
        if category:
            return category, reason, "call", line, chain, 0, fixed

    name = getattr(fn, "name", "")
    doc = ast.get_docstring(fn) if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) else ""
    category, reason = _sink_from_name(name, doc or "")
    if category:
        # No observed call, so the action is the whole function. Anchoring the
        # "sink line" past the end of the body means a guard anywhere inside it
        # counts as preceding the action -- which is true, and the opposite of
        # the old behaviour, which anchored on the `def` line and so reported
        # every guard in the body as arriving "after the sink".
        end = getattr(fn, "end_lineno", None) or getattr(fn, "lineno", 0)
        return category, reason, "declared", end + 1, [], 0, False

    return "", "", "", 0, [], 0, False

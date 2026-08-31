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

__all__ = ["SINK_CALLS", "SHELL_ARGV", "EXEC_CALLS", "NAME_HINTS", "classify_function"]

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
    "update_service": "NETWORK",
    # Money
    "create_refund": "MONEY",
    "refund": "MONEY",
    "capture": "MONEY",
    "create_payout": "MONEY",
    "create_transfer": "MONEY",
    "cancel_subscription": "MONEY",
    # Schema
    "execute_ddl": "DATABASE",
    "run_migration": "DATABASE",
    "upgrade": "DATABASE",
    "downgrade": "DATABASE",
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

#: Calls that hand a command to the operating system.
EXEC_CALLS: frozenset[str] = frozenset(
    {"run", "Popen", "call", "check_call", "check_output", "system", "spawn", "exec_command"}
)

#: Ordered name/docstring keywords -> category. Order matters: the first match
#: wins, so the more specific keywords come first.
NAME_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("drop", "purge", "truncate", "wipe", "delete_all"), "DATA_LOSS"),
    (("terminate", "teardown", "decommission", "delete_cluster", "delete_node"), "COMPUTE"),
    (("rollback", "deploy", "redeploy", "restart", "scale"), "DEPLOYMENT"),
    (("failover", "reroute", "cutover", "dns", "traffic_shift"), "NETWORK"),
    (("rotate", "credential", "secret", "grant_access", "revoke"), "IDENTITY"),
    (("migration", "migrate", "schema_change"), "DATABASE"),
    (("refund", "payout", "chargeback", "disburse"), "MONEY"),
)


def _final_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _shell_token(call: ast.Call) -> str:
    """First shell token of a subprocess-style call, if statically known."""
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            parts = arg.value.strip().split()
            return parts[0] if parts else ""
        if isinstance(arg, ast.List) and arg.elts:
            first = arg.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        break
    return ""


def _sink_from_body(fn: ast.AST) -> tuple[str, str, int]:
    """First recognised sink call: (category, reason, line). Line 0 if none."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _final_name(node)
        if name in SINK_CALLS:
            return SINK_CALLS[name], f"calls {name}()", node.lineno
        if name in EXEC_CALLS:
            token = _shell_token(node)
            if token in SHELL_ARGV:
                return SHELL_ARGV[token], f"shells out to {token}", node.lineno
            if token:
                return "EXECUTION", f"shell/exec via {name}() running {token}", node.lineno
            return "EXECUTION", f"shell/exec via {name}()", node.lineno
    return "", "", 0


def _sink_from_name(name: str, doc: str) -> tuple[str, str]:
    haystack = f"{name} {doc or ''}".lower()
    for keywords, category in NAME_HINTS:
        for keyword in keywords:
            if keyword in haystack:
                return category, f"declared action ({keyword})"
    return "", ""


def classify_function(fn: ast.AST) -> tuple[str, str, str, int]:
    """Classify a function's consequence.

    Returns (category, reason, confidence, sink_line). Category is "" when the
    function is not a recognised consequential action.
    """
    category, reason, line = _sink_from_body(fn)
    if category:
        return category, reason, "call", line

    name = getattr(fn, "name", "")
    doc = ast.get_docstring(fn) if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) else ""
    category, reason = _sink_from_name(name, doc or "")
    if category:
        # No observed call, so the whole function body is the location.
        return category, reason, "declared", getattr(fn, "lineno", 0)

    return "", "", "", 0

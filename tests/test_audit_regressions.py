"""Regression tests for every failure the pre-Show-HN audit found on real code.

Each case here was observed on a public repository or reduced from one. They
are the cases a skeptical reader is most likely to try, so they are pinned as
tests rather than left to manual verification.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

from kiff_scan.engine import scan_path

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
NEGATIVES = os.path.join(FIXTURES, "negatives")
POSITIVES = os.path.join(FIXTURES, "positives")
EVIDENCE = os.path.join(FIXTURES, "evidence")


def _tools(path: str) -> dict[str, object]:
    return {f.tool: f for f in scan_path(path).findings}


# --------------------------------------------------------------------------
# Precision: the false positives that were quotable one-liners.
# --------------------------------------------------------------------------


def test_agent_run_is_not_shell_execution():
    """`agent.run()` is delegation, not execution.

    On pydantic-ai this produced 8 of 10 findings, every one HIGH severity
    "Shell / execution". It is the single most common method name in the
    ecosystem, so matching `run` regardless of receiver cannot work.
    """
    found = _tools(os.path.join(NEGATIVES, "agent_run.py"))
    assert "ask_specialist" not in found
    assert "ask_specialist_async" not in found


def test_console_capture_is_not_money_movement():
    """rich's `Console.capture()` is output buffering, not a payment capture."""
    assert "render_panel" not in _tools(os.path.join(NEGATIVES, "agent_run.py"))


def test_bare_call_is_not_execution():
    """`client.call(payload)` on an arbitrary object is not a subprocess."""
    assert "call_helper" not in _tools(os.path.join(NEGATIVES, "agent_run.py"))


def test_dropdown_is_not_data_loss():
    """'drop' is a token of `drop_database` and not of `select_dropdown`.

    Both browser-use findings were this: substring matching over the name.
    """
    found = _tools(os.path.join(NEGATIVES, "readonly_names.py"))
    assert "select_dropdown" not in found
    assert "dropdown_options" not in found


def test_read_only_tools_are_not_flagged_from_incidental_words():
    """A read tool whose docs happen to say truncate/scale/credential/secret.

    These were roughly 40 of the 61 findings on awslabs/mcp.
    """
    found = _tools(os.path.join(NEGATIVES, "readonly_names.py"))
    for tool in (
        "read_documentation",
        "list_columns_tool",
        "get_aws_account_info",
        "get_secret_word",
        "get_weather",
        "check_deploy_status",
        "validate_upgrade_plan",
    ):
        assert tool not in found, f"{tool} is read-only and must not be a finding"


def test_negatives_are_completely_clean():
    """The whole negative corpus, minus the Celery module, reports nothing."""
    findings = [
        f
        for f in scan_path(NEGATIVES).findings
        if not f.file.endswith("celery_tasks.py")
    ]
    assert findings == []


def test_generic_task_decorator_without_agent_framework_is_not_reachable():
    """A Celery repo with no LLM in it has no agent blast radius.

    `@app.task` is a unit of work. Treating it as model exposure turns every
    backend into an agent.
    """
    assert _tools(os.path.join(NEGATIVES, "celery_tasks.py")) == {}


# --------------------------------------------------------------------------
# Recall: the canonical dangerous tools that scanned clean.
# --------------------------------------------------------------------------


def test_python_repl_and_eval_are_execution():
    """A REPL tool is the first example in every agent-security talk."""
    found = _tools(os.path.join(POSITIVES, "exec_tools.py"))
    assert found["python_repl"].category == "EXECUTION"
    assert found["evaluate"].category == "EXECUTION"


def test_os_exec_family_is_execution():
    """Strands' `shell` tool reaches `os.execvp`, which was not a sink."""
    assert _tools(os.path.join(POSITIVES, "exec_tools.py"))["shell"].category == "EXECUTION"


def test_asyncio_subprocess_and_pexpect_are_execution():
    found = _tools(os.path.join(POSITIVES, "exec_tools.py"))
    assert found["run_async"].category == "EXECUTION"
    assert found["run_async_exec"].category == "EXECUTION"
    assert found["spawn_login"].category == "EXECUTION"


def test_subprocess_with_shell_true_is_execution():
    assert _tools(os.path.join(POSITIVES, "exec_tools.py"))["run_subprocess"].category == "EXECUTION"


def test_class_based_tools_are_reachable():
    """LangChain and CrewAI tools are classes; their action lives in `_run`."""
    found = _tools(os.path.join(POSITIVES, "class_tools.py"))
    assert "_run" in found
    assert "_arun" in found
    assert any("subclass" in f.reachable_by for f in found.values())


def test_function_registration_shapes_are_reachable():
    """`StructuredTool.from_function(fn)` and `Tool(func=fn)`."""
    found = _tools(os.path.join(POSITIVES, "class_tools.py"))
    assert "wipe" in found
    assert "terminate" in found


def test_tool_plain_call_tool_and_kernel_function():
    """pydantic-ai, low-level MCP and Semantic Kernel registration."""
    found = _tools(os.path.join(POSITIVES, "registration_shapes.py"))
    assert found["nuke"].category == "DATA_LOSS"
    assert "remove_path" in found
    assert "rotate_key" in found


def test_method_registered_by_call_is_reachable():
    """`self.mcp.tool(name=...)(self.method)` -- the awslabs eks handler shape."""
    assert "manage_k8s_resource" in _tools(os.path.join(POSITIVES, "registration_shapes.py"))


# --------------------------------------------------------------------------
# Evidence: claims that were false in the accusatory direction.
# --------------------------------------------------------------------------


def test_declared_action_credits_a_guard_in_the_body():
    """A declared finding anchored its sink on the `def` line.

    Every guard in the body was therefore "after the sink" -- a false and
    checkable accusation about the claim this product leads with.
    """
    finding = _tools(os.path.join(EVIDENCE, "ordering.py"))["rollback_release"]
    assert finding.governed, "require_approval() precedes the declared action"
    assert "after the sink" not in finding.evidence.detail


def test_same_line_guard_is_credited():
    """`if authorize(x): delete(x)` -- guard and sink share a line."""
    finding = _tools(os.path.join(EVIDENCE, "ordering.py"))["drop_it"]
    assert finding.governed
    assert "after the sink" not in finding.evidence.detail


def test_framework_native_approval_is_decision_evidence():
    """agno's `requires_confirmation=True` and the OpenAI SDK's
    `needs_approval=True` are decision boundaries in framework vocabulary.

    Reporting agno's `human_in_the_loop/` examples as ungoverned was the most
    embarrassing result in the audit corpus.
    """
    found = _tools(os.path.join(EVIDENCE, "framework_approval.py"))
    for tool in ("delete_bucket", "rotate_secret", "terminate_instance"):
        assert found[tool].governed, f"{tool} declares a human-in-the-loop boundary"
        assert found[tool].evidence.kind.value == "framework_approval"


def test_read_only_annotation_suppresses_a_genuine_read():
    """`readOnlyHint=True` on a tool that really only reads is believed."""
    assert "describe_bucket" not in _tools(os.path.join(EVIDENCE, "annotation_mismatch.py"))


def test_annotation_mismatch_is_reported_distinctly():
    """A tool that says read-only and calls delete_table() is the wow case."""
    finding = _tools(os.path.join(EVIDENCE, "annotation_mismatch.py"))["inspect_table"]
    assert finding.annotation_mismatch is True
    assert finding.annotations.get("readOnlyHint") is True


def test_destructive_hint_surfaces_the_tool():
    """awslabs' `call_aws` declares destructiveHint=True and runs any CLI."""
    finding = _tools(os.path.join(EVIDENCE, "annotation_mismatch.py"))["call_aws"]
    assert finding.confidence == "annotated"


# --------------------------------------------------------------------------
# CLI and report surfaces.
# --------------------------------------------------------------------------


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=os.path.join(root, "src"))
    return subprocess.run(
        [sys.executable, "-m", "kiff_scan", *args],
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
    )


def test_printed_next_command_actually_runs():
    """The report's own instruction is the first thing a user copies.

    It printed a path relative to the scan root, so running it from anywhere
    else exited 2 with 'file not found'.
    """
    scan = _run("scan", "tests/fixtures/ungoverned_ops.py")
    match = re.search(r"Next:\s*\n\s*kiff-scan (.+)", scan.stdout)
    assert match, f"no Next: line in report:\n{scan.stdout}"

    followup = _run(*match.group(1).split())
    assert followup.returncode == 0, f"printed command failed: {followup.stderr}"


def test_clean_scan_does_not_claim_it_established_a_path():
    """A scan with no findings must not say it found one."""
    out = _run("scan", "tests/fixtures/negatives/readonly_names.py").stdout
    assert "found no supported path" in out
    assert "This scan established that" not in out


def test_scan_with_findings_keeps_the_established_wording():
    out = _run("scan", "tests/fixtures/ungoverned_ops.py").stdout
    assert "This scan established that" in out

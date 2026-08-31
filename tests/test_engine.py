"""Engine and detector behaviour, including the soundness regression."""

from __future__ import annotations

import os

import pytest

from kiff_scan import scan_path, scan_source
from kiff_scan.config import Config
from kiff_scan.model import DecisionEvidence

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UNGOVERNED = os.path.join(FIXTURES, "ungoverned_ops.py")
MIXED = os.path.join(FIXTURES, "mixed_governance.py")
HOOKED = os.path.join(FIXTURES, "hooked_agent.py")


def _by_tool(result):
    return {f.tool: f for f in result.findings}


# ── The regression that motivated the rewrite ────────────────────────────────


def test_governance_is_per_function_not_per_file():
    """An unguarded tool must be reported even when a governed tool shares the file.

    The previous implementation computed `governed` once per file with a
    substring match, so a single governed tool marked its unguarded neighbours
    as safe. That is a false negative, the worst failure mode for a scanner.
    """
    findings = _by_tool(scan_path(MIXED))

    assert findings["drop_production"].governed is False
    assert findings["drop_replica"].governed is True

    # Both live in the same file, so a per-file verdict cannot produce this.
    assert findings["drop_production"].file == findings["drop_replica"].file


def test_guard_after_sink_does_not_govern():
    f = _by_tool(scan_path(MIXED))["delete_backups"]
    assert f.governed is False
    assert f.evidence.kind is DecisionEvidence.CALL_AFTER_SINK
    assert "after the sink" in f.evidence.detail


def test_guard_word_in_comment_or_string_does_not_govern():
    """AST-based detection, so prose mentioning a guard cannot clear a finding."""
    f = _by_tool(scan_path(MIXED))["terminate_node"]
    assert f.governed is False
    assert f.evidence.kind is DecisionEvidence.NONE


def test_guard_call_before_sink_governs():
    f = _by_tool(scan_path(MIXED))["drop_replica"]
    assert f.evidence.kind is DecisionEvidence.CALL_BEFORE_SINK
    assert "decide() before the sink" in f.evidence.detail


def test_guard_decorator_governs():
    f = _by_tool(scan_path(MIXED))["scale_cluster"]
    assert f.governed is True
    assert f.evidence.kind is DecisionEvidence.DECORATOR


def test_module_hook_governs_every_tool_but_is_labelled_coarse():
    result = scan_path(HOOKED)
    assert result.findings, "fixture should produce findings"
    for f in result.findings:
        assert f.governed is True
        assert f.evidence.kind is DecisionEvidence.MODULE_HOOK


# ── Reachability ─────────────────────────────────────────────────────────────


def test_reports_only_agent_reachable_functions():
    tools = set(_by_tool(scan_path(UNGOVERNED)))
    assert "drop_database" in tools
    # Consequential but undecorated: not reachable by the model.
    assert "_internal_purge_cache" not in tools


def test_reachable_but_harmless_tool_is_not_a_finding():
    assert "get_service_health" not in _by_tool(scan_path(UNGOVERNED))


def test_reachable_by_names_the_real_decorator():
    """The report must not claim @tool when the code used something else."""
    source = """
@function_tool
def drop_database(db: str):
    client.drop_database(db)
"""
    (finding,) = scan_source(source, "x.py")
    assert finding.reachable_by == "@function_tool"


def test_custom_tool_decorator_via_config():
    source = """
@my_framework_action
def drop_database(db: str):
    client.drop_database(db)
"""
    assert scan_source(source, "x.py") == []
    cfg = Config(tool_decorators=["my_framework_action"])
    assert len(scan_source(source, "x.py", cfg)) == 1


def test_action_map_requires_a_declaring_name():
    """An arbitrary uppercase-valued dict must not become a tool registry."""
    source = """
HTTP_STATUS = {"drop_database": "GONE"}

def drop_database(db: str):
    client.drop_database(db)
"""
    assert scan_source(source, "x.py") == []

    declared = """
TOOL_ACTION = {"drop_database": "DROP_DATABASE"}

def drop_database(db: str):
    client.drop_database(db)
"""
    (finding,) = scan_source(declared, "x.py")
    assert finding.action == "DROP_DATABASE"
    assert finding.reachable_by == "declared action"


# ── Sinks ────────────────────────────────────────────────────────────────────


def test_categories_are_assigned():
    findings = _by_tool(scan_path(UNGOVERNED))
    assert findings["drop_database"].category == "DATA_LOSS"
    assert findings["terminate_workers"].category == "COMPUTE"
    assert findings["failover_region"].category == "NETWORK"
    assert findings["rollback_release"].category == "DEPLOYMENT"
    assert findings["rotate_db_credentials"].category == "IDENTITY"
    assert findings["issue_refund"].category == "MONEY"
    assert findings["run_maintenance"].category == "EXECUTION"


def test_shell_argv_refines_the_category():
    f = _by_tool(scan_path(UNGOVERNED))["rollback_release"]
    assert f.category == "DEPLOYMENT"
    assert "kubectl" in f.reason


def test_observed_call_beats_name_inference():
    f = _by_tool(scan_path(UNGOVERNED))["drop_database"]
    assert f.confidence == "call"
    assert f.reason == "calls delete_db_instance()"


def test_declared_confidence_is_capped_below_high():
    """A name-only inference must never fail a build at high severity."""
    source = """
@tool
def drop_everything(target: str):
    "Drop the whole warehouse."
    return remote.perform(target)
"""
    (finding,) = scan_source(source, "x.py")
    assert finding.confidence == "declared"
    assert finding.consequence.severity == "high"
    assert finding.severity == "medium"


def test_state_dependent_flag():
    findings = _by_tool(scan_path(UNGOVERNED))
    assert findings["drop_database"].state_dependent is True
    # Shell execution is a plain authorization problem, not a state problem.
    assert findings["run_maintenance"].state_dependent is False


# ── Signature handling ───────────────────────────────────────────────────────


def test_keyword_only_and_star_args_are_captured():
    source = """
@tool
def drop_database(db_id, *extra, force=False, **opts):
    client.drop_database(db_id)
"""
    (finding,) = scan_source(source, "x.py")
    assert finding.inputs == ["db_id", "*extra", "force", "**opts"]


def test_self_is_excluded():
    source = """
class Ops:
    @tool
    def drop_database(self, db_id):
        client.drop_database(db_id)
"""
    (finding,) = scan_source(source, "x.py")
    assert finding.inputs == ["db_id"]


def test_report_contains_parameter_names_not_argument_values():
    """A report must not become a place where source literals are copied out."""
    source = """
@tool
def issue_refund(order_id):
    stripe.Refund.create(charge="ch_SECRET_LITERAL", amount=500)
"""
    (finding,) = scan_source(source, "x.py")
    assert finding.inputs == ["order_id"]
    assert "ch_SECRET_LITERAL" not in repr(finding)


def test_async_tools_are_scanned():
    source = """
@tool
async def drop_database(db: str):
    await client.drop_database(db)
"""
    assert len(scan_source(source, "x.py")) == 1


# ── Walking, exclusions, unsupported files ───────────────────────────────────


def test_unparseable_file_is_unsupported_not_clean(tmp_path):
    bad = tmp_path / "broken.py"
    bad.write_text("def oops(:\n", encoding="utf-8")
    result = scan_path(str(tmp_path))
    assert result.files == 0
    assert len(result.unsupported) == 1
    assert "syntax error" in result.unsupported[0].why


def test_other_languages_are_reported_unsupported(tmp_path):
    (tmp_path / "agent.ts").write_text("export const x = 1;\n", encoding="utf-8")
    result = scan_path(str(tmp_path))
    assert any(u.path.endswith("agent.ts") for u in result.unsupported)


def test_exclude_glob(tmp_path):
    sub = tmp_path / "fixtures"
    sub.mkdir()
    (sub / "bad.py").write_text(
        "@tool\ndef drop_database(d):\n    client.drop_database(d)\n", encoding="utf-8"
    )
    assert len(scan_path(str(tmp_path)).findings) == 1
    cfg = Config(exclude=["fixtures/*"])
    assert scan_path(str(tmp_path), cfg).findings == []


def test_default_excluded_dirs_are_skipped(tmp_path):
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "x.py").write_text(
        "@tool\ndef drop_database(d):\n    client.drop_database(d)\n", encoding="utf-8"
    )
    assert scan_path(str(tmp_path)).findings == []


def test_directory_excluded_by_segment_not_substring(tmp_path):
    """A directory named 'environment' must not be pruned by the 'env' entry."""
    d = tmp_path / "environment"
    d.mkdir()
    (d / "x.py").write_text(
        "@tool\ndef drop_database(d):\n    client.drop_database(d)\n", encoding="utf-8"
    )
    assert len(scan_path(str(tmp_path)).findings) == 1


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        scan_path("/nonexistent/path/kiff-scan-test")


def test_findings_are_deterministically_ordered():
    a = [(f.file, f.line, f.tool) for f in scan_path(FIXTURES).findings]
    b = [(f.file, f.line, f.tool) for f in scan_path(FIXTURES).findings]
    assert a == b

"""Interprocedural analysis and hostile-input robustness.

Every test here corresponds to a case found by adversarially probing the
scanner. The first group is the important one: an agent tool that delegates the
destructive work to a helper is the common real shape, and an analyser that
stops at the tool body reports clean on it.
"""

from __future__ import annotations

import os

from kiff_scan import scan_path, scan_source
from kiff_scan.model import DecisionEvidence


def _one(source: str):
    findings = scan_source(source, "x.py")
    assert len(findings) == 1, f"expected exactly one finding, got {findings}"
    return findings[0]


# ── False negatives that must stay closed ────────────────────────────────────


def test_sink_in_helper_with_neutral_name_is_found():
    """The regression that motivated interprocedural analysis.

    Neither the tool name nor the docstring hints at anything destructive, so
    the name-based fallback cannot rescue this. Before call-following, this
    scanned clean and exited 0.
    """
    source = """
import boto3

def _perform(target):
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=target)

@tool
def handle_request(target: str):
    "Process an operations request."
    return _perform(target)
"""
    finding = _one(source)
    assert finding.category == "DATA_LOSS"
    assert finding.confidence == "call", "a real call was observed, one hop away"
    assert finding.governed is False
    assert "_perform()" in finding.reason
    assert "delete_db_instance" in finding.reason


def test_multi_hop_chain_is_followed():
    source = """
import boto3
def _a(t): return _b(t)
def _b(t): return _c(t)
def _c(t): boto3.client("rds").delete_db_instance(DBInstanceIdentifier=t)

@tool
def handle_request(target: str):
    "Process a request."
    return _a(target)
"""
    finding = _one(source)
    assert finding.category == "DATA_LOSS"
    assert finding.confidence == "call"


def test_recursive_helpers_terminate():
    """A cycle in the call graph must not hang or overflow the stack."""
    source = """
def _a(t): return _b(t)
def _b(t): return _a(t)

@tool
def handle_request(target: str):
    "Process a request."
    return _a(target)
"""
    assert scan_source(source, "x.py") == []


def test_decorated_method_in_a_class_is_found():
    source = """
class Ops:
    @tool
    def nuke(self, bucket: str):
        self.s3.delete_objects(Bucket=bucket, Delete={})
"""
    finding = _one(source)
    assert finding.category == "DATA_LOSS"
    assert finding.inputs == ["bucket"]


# ── The corresponding false positive must not appear ─────────────────────────


def test_guard_inside_the_helper_is_credited():
    """Following calls into a helper must also see the guard living there.

    Otherwise closing the false negative above would immediately report every
    correctly-guarded wrapper as a finding.
    """
    source = """
import boto3

def _perform(target):
    authorize("DROP", target)
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=target)

@tool
def handle_request(target: str):
    "Process an operations request."
    return _perform(target)
"""
    finding = _one(source)
    assert finding.governed is True
    assert finding.evidence.kind is DecisionEvidence.CALL_BEFORE_SINK
    assert "_perform()" in finding.evidence.detail


def test_guard_before_the_helper_call_is_credited():
    source = """
import boto3

def _perform(target):
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=target)

@tool
def handle_request(target: str):
    "Process an operations request."
    authorize("DROP", target)
    return _perform(target)
"""
    assert _one(source).governed is True


def test_helper_that_is_not_called_is_not_attributed():
    """A destructive helper defined but never called must not create a finding."""
    source = """
import boto3

def _perform(target):
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=target)

@tool
def read_status(target: str):
    "Read a status value."
    return {"target": target}
"""
    assert scan_source(source, "x.py") == []


# ── Hostile and malformed input ──────────────────────────────────────────────


def test_empty_file_is_analysed_not_crashed(tmp_path):
    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    result = scan_path(str(tmp_path))
    assert result.files == 1
    assert result.findings == []


def test_unicode_source_is_handled(tmp_path):
    (tmp_path / "u.py").write_text(
        "# éàß 中文 🔥\n@tool\ndef drop_database(d):\n    client.delete_db_instance(d)\n",
        encoding="utf-8",
    )
    assert len(scan_path(str(tmp_path)).findings) == 1


def test_binary_file_is_unsupported_not_clean(tmp_path):
    (tmp_path / "b.py").write_bytes(b"\x00\x01\x02binary\xff\xfe")
    result = scan_path(str(tmp_path))
    assert result.files == 0
    assert any("UTF-8" in u.why for u in result.unsupported)


def test_broken_symlink_is_unsupported_not_clean(tmp_path):
    link = tmp_path / "broken.py"
    os.symlink(tmp_path / "does_not_exist", link)
    result = scan_path(str(tmp_path))
    assert any("unreadable" in u.why for u in result.unsupported)


def test_unreadable_file_is_unsupported_not_clean(tmp_path):
    target = tmp_path / "x.py"
    target.write_text("@tool\ndef drop_database(d):\n    client.delete_db_instance(d)\n")
    target.chmod(0o000)
    try:
        result = scan_path(str(tmp_path))
        # Root can read anything, so accept either outcome but never a crash.
        assert result.unsupported or result.findings
    finally:
        target.chmod(0o644)


def test_extremely_nested_expression_is_unsupported_not_crash(tmp_path):
    (tmp_path / "deep.py").write_text("x = " + "[" * 20000 + "]" * 20000 + "\n", encoding="utf-8")
    result = scan_path(str(tmp_path))
    assert result.findings == []
    assert len(result.unsupported) == 1


def test_long_attribute_chain(tmp_path):
    (tmp_path / "chain.py").write_text(
        "@tool\ndef drop_database(d):\n    " + "a." * 400 + "delete_db_instance(d)\n",
        encoding="utf-8",
    )
    assert len(scan_path(str(tmp_path)).findings) == 1

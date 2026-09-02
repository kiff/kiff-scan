"""Governability derivation and report rendering."""

from __future__ import annotations

import json
import os

import pytest

from kiff_scan import EvidenceState, Readiness, assess, scan_path
from kiff_scan.report.assessment import (
    assessment_to_html,
    assessment_to_json,
    assessment_to_markdown,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UNGOVERNED = os.path.join(FIXTURES, "ungoverned_ops.py")
HOOKED = os.path.join(FIXTURES, "hooked_agent.py")
APPROVAL = os.path.join(FIXTURES, "evidence", "framework_approval.py")
MISMATCH = os.path.join(FIXTURES, "evidence", "annotation_mismatch.py")
STAMP = "2026-09-02T12:00:00Z"
COMMIT = "a" * 40


def _assessment(path: str):
    return assess(scan_path(path), path, generated_at=STAMP, repository_commit=COMMIT)


def _dimension(report, dimension_id):
    return next(dimension for dimension in report.dimensions if dimension.id == dimension_id)


def test_high_unguarded_paths_are_hard_blockers():
    report = _assessment(UNGOVERNED)

    assert report.readiness is Readiness.NOT_READY
    assert report.blockers
    assert all(blocker.file == UNGOVERNED for blocker in report.blockers)
    assert {blocker.code for blocker in report.blockers} == {"high_consequence_without_decision"}


def test_governed_paths_remain_conditional_when_evidence_is_not_assessable():
    report = _assessment(HOOKED)

    assert report.blockers == []
    assert report.readiness is Readiness.CONDITIONAL
    assert _dimension(report, "decision_coverage").state is EvidenceState.EVIDENCED
    assert _dimension(report, "operational_state").state is EvidenceState.NOT_ASSESSABLE
    assert _dimension(report, "traceability").state is EvidenceState.NOT_ASSESSABLE


def test_framework_approval_is_human_authority_evidence():
    report = _assessment(APPROVAL)
    dimension = _dimension(report, "human_authority")

    assert dimension.state is EvidenceState.EVIDENCED
    assert "3 of 3" in dimension.evidence[0]


def test_annotation_mismatch_is_a_hard_blocker():
    report = _assessment(MISMATCH)

    assert report.readiness is Readiness.NOT_READY
    assert any(blocker.code == "contradictory_annotation" for blocker in report.blockers)


def test_unsupported_source_prevents_complete_inventory(tmp_path):
    (tmp_path / "agent.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "agent.ts").write_text("export const x = 1;\n", encoding="utf-8")
    report = _assessment(str(tmp_path))

    assert _dimension(report, "action_inventory").state is EvidenceState.PARTIAL
    assert report.readiness is Readiness.CONDITIONAL


def test_empty_supported_scope_is_not_assessable(tmp_path):
    report = _assessment(str(tmp_path))

    assert _dimension(report, "action_inventory").state is EvidenceState.NOT_ASSESSABLE
    assert report.readiness is Readiness.CONDITIONAL


def test_json_is_versioned_and_separates_conclusions_from_evidence():
    payload = json.loads(assessment_to_json(_assessment(UNGOVERNED)))

    assert payload["schema_version"] == 1
    assert payload["report_type"] == "kiff_agent_governability_assessment"
    assert payload["conclusion"]["readiness"] == "not_ready"
    assert payload["hard_blockers"]
    assert payload["evidence"]["actions"]
    assert payload["claim_boundary"]
    assert payload["metadata"]["generated_at"] == STAMP
    assert payload["metadata"]["repository_commit"] == COMMIT


def test_markdown_contains_management_sections_and_claim_boundary():
    rendered = assessment_to_markdown(_assessment(MISMATCH))

    for heading in (
        "Executive summary",
        "Hard blockers",
        "Governability scorecard",
        "Consequential-action register",
        "Evidence paths",
        "Contradictions and weak evidence",
        "Prioritized remediation",
        "Scope and claim boundary",
        "Reproducibility",
    ):
        assert heading in rendered
    assert "not a compliance certification" in rendered


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows filenames cannot contain '<' or '>'. The escaping this asserts is "
    "covered on every platform by test_html_escapes_hostile_target_path below.",
)
def test_html_is_self_contained_and_escapes_source_metadata(tmp_path):
    target = tmp_path / "agent<script>.py"
    target.write_text(
        "@tool\ndef drop_database(db):\n    client.drop_database(db)\n", encoding="utf-8"
    )
    rendered = assessment_to_html(_assessment(str(target)))

    assert "<!doctype html>" in rendered
    assert "Evidence paths" in rendered
    assert "<script>" not in rendered
    assert "agent&lt;script&gt;.py" in rendered
    assert "http://" not in rendered
    assert "https://" not in rendered


def test_html_escapes_hostile_source_paths_cross_platform():
    """Escaping must hold on every platform, including where the filesystem
    refuses to create a hostile filename.

    Finding.file is the untrusted-metadata channel the on-disk test above
    exercises through a real filename. Windows cannot represent '<' in a
    filename, so that test is skipped there and this one carries the assertion:
    it scans a normally-named fixture, then substitutes the hostile value into
    the scan result before rendering.
    """
    result = scan_path(UNGOVERNED)
    assert result.findings, "fixture should produce findings to carry the payload"
    hostile = "agent<script>alert('xss')</script>.py"
    for finding in result.findings:
        finding.file = hostile

    rendered = assessment_to_html(
        assess(result, hostile, generated_at=STAMP, repository_commit=COMMIT)
    )

    assert "<script>" not in rendered
    assert "alert('xss')" not in rendered
    assert "agent&lt;script&gt;" in rendered

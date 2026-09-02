"""CLI behaviour, exit codes, and reporter output."""

from __future__ import annotations

import json
import os

from kiff_scan import scan_path, to_json, to_markdown, to_sarif
from kiff_scan.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UNGOVERNED = os.path.join(FIXTURES, "ungoverned_ops.py")
HOOKED = os.path.join(FIXTURES, "hooked_agent.py")


# ── Exit codes ───────────────────────────────────────────────────────────────


def test_exit_1_on_findings_at_default_threshold(capsys):
    assert main(["scan", UNGOVERNED]) == EXIT_FINDINGS
    capsys.readouterr()


def test_exit_0_when_all_findings_are_governed(capsys):
    assert main(["scan", HOOKED]) == EXIT_OK
    capsys.readouterr()


def test_fail_on_none_never_fails(capsys):
    assert main(["scan", UNGOVERNED, "--fail-on", "none"]) == EXIT_OK
    capsys.readouterr()


def test_fail_on_high_only_fails_on_high(capsys):
    """A 'declared'-confidence finding is capped at medium, so it must not fail
    a --fail-on high run on its own."""
    assert main(["scan", UNGOVERNED, "--fail-on", "high"]) == EXIT_FINDINGS
    capsys.readouterr()


def test_exit_2_on_missing_path(capsys):
    assert main(["scan", "/nonexistent/kiff-scan-path"]) == EXIT_USAGE
    assert "path not found" in capsys.readouterr().err


def test_exit_2_on_bad_config(tmp_path, capsys):
    cfg = tmp_path / "bad.json"
    cfg.write_text("{not json", encoding="utf-8")
    assert main(["scan", UNGOVERNED, "--config", str(cfg)]) == EXIT_USAGE
    assert "cannot read" in capsys.readouterr().err


def test_bare_path_is_shorthand_for_scan(capsys):
    assert main([UNGOVERNED]) == EXIT_FINDINGS
    assert "BLAST RADIUS" in capsys.readouterr().out


def test_guard_flag_clears_a_finding(tmp_path, capsys):
    target = tmp_path / "agent.py"
    target.write_text(
        "@tool\n"
        "def drop_database(db):\n"
        "    acme_authorize('DROP', db)\n"
        "    client.drop_database(db)\n",
        encoding="utf-8",
    )
    assert main(["scan", str(target)]) == EXIT_FINDINGS
    capsys.readouterr()
    assert main(["scan", str(target), "--guard", "acme_authorize"]) == EXIT_OK
    capsys.readouterr()


# ── explain ──────────────────────────────────────────────────────────────────


def test_explain_prints_the_path(capsys):
    result = scan_path(UNGOVERNED)
    target = next(f for f in result.findings if f.tool == "drop_database")
    assert main(["explain", f"{UNGOVERNED}:{target.line}"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Agent entry point" in out
    assert "Consequential call" in out
    assert "does not establish" in out


def test_explain_rejects_a_bad_location(capsys):
    assert main(["explain", "not-a-location"]) == EXIT_USAGE
    assert "expected FILE:LINE" in capsys.readouterr().err


def test_explain_lists_alternatives_when_line_is_wrong(capsys):
    assert main(["explain", f"{UNGOVERNED}:9999"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "no finding at" in err
    assert "findings in this file" in err


# ── Reporters ────────────────────────────────────────────────────────────────


def test_json_is_valid_and_documents_its_limits():
    payload = json.loads(to_json(scan_path(UNGOVERNED), UNGOVERNED))
    assert payload["schema_version"] == 1
    assert payload["summary"]["review_required"] > 0
    assert payload["not_established"]
    for finding in payload["findings"]:
        assert set(finding) >= {"rule_id", "severity", "state_dependent", "decision_evidence"}


def test_sarif_shape_is_valid():
    payload = json.loads(to_sarif(scan_path(UNGOVERNED), UNGOVERNED))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "kiff-scan"
    assert run["results"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids, "every result must reference a declared rule"
        assert result["level"] in ("error", "warning", "note")
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_excludes_governed_findings():
    payload = json.loads(to_sarif(scan_path(HOOKED), HOOKED))
    assert payload["runs"][0]["results"] == []


def test_markdown_contains_the_limits_note():
    md = to_markdown(scan_path(UNGOVERNED), UNGOVERNED)
    assert "kiff-scan" in md
    assert "did not establish" in md


def test_pretty_report_states_what_it_did_not_establish(capsys):
    main(["scan", UNGOVERNED])
    out = capsys.readouterr().out
    assert "What this scan did not establish" in out
    assert "not that the code is safe" in out


def test_pretty_report_shows_decision_evidence(capsys):
    main(["scan", os.path.join(FIXTURES, "mixed_governance.py")])
    out = capsys.readouterr().out
    assert "cleared, with evidence" in out
    assert "after the" in out  # the guard-after-sink warning


def test_output_flag_writes_a_file(tmp_path, capsys):
    out = tmp_path / "nested" / "report.json"
    main(["scan", UNGOVERNED, "--format", "json", "--output", str(out)])
    capsys.readouterr()
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == 1


def test_assess_writes_versioned_json_and_fails_on_hard_blockers(tmp_path, capsys):
    out = tmp_path / "assessment.json"
    assert main(["assess", UNGOVERNED, "--format", "json", "--output", str(out)]) == EXIT_FINDINGS
    capsys.readouterr()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["report_type"] == "kiff_agent_governability_assessment"
    assert payload["conclusion"]["readiness"] == "not_ready"


def test_assess_governed_code_is_conditional_and_exits_zero(capsys):
    assert main(["assess", HOOKED]) == EXIT_OK
    out = capsys.readouterr().out
    assert "CONDITIONAL" in out
    assert "not a compliance certification" in out


def test_assess_writes_self_contained_html(tmp_path, capsys):
    out = tmp_path / "assessment.html"
    assert main(["assess", HOOKED, "--format", "html", "--output", str(out)]) == EXIT_OK
    capsys.readouterr()
    rendered = out.read_text(encoding="utf-8")
    assert rendered.startswith("<!doctype html>")
    assert "Governability scorecard" in rendered


def test_show_unsupported_lists_files(tmp_path, capsys):
    (tmp_path / "agent.ts").write_text("const x = 1;\n", encoding="utf-8")
    main(["scan", str(tmp_path), "--show-unsupported"])
    assert "agent.ts" in capsys.readouterr().err


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "kiff-scan" in capsys.readouterr().out


def test_evidence_command_and_deprecated_assess_alias(capsys):
    """`assess` was renamed to `evidence`. The old name must keep working so
    existing CI does not break, but it warns and is hidden from help — the
    rename exists to stop this command colliding with the agentic KIFF
    governance audit, which executes code and attacks claimed guarantees."""
    # The fixture carries hard blockers, so the command reports findings.
    assert main(["evidence", UNGOVERNED, "--format", "markdown"]) == EXIT_FINDINGS
    fresh = capsys.readouterr()
    assert "Agent Governability Evidence" in fresh.out
    assert "deprecated" not in fresh.err

    assert main(["assess", UNGOVERNED, "--format", "markdown"]) == EXIT_FINDINGS
    aliased = capsys.readouterr()

    def _without_timestamp(text: str) -> list[str]:
        return [line for line in text.splitlines() if not line.startswith("- Generated:")]

    assert _without_timestamp(aliased.out) == _without_timestamp(
        fresh.out
    ), "alias must be behaviourally identical apart from the generation time"
    assert "deprecated" in aliased.err
    assert "kiff-scan evidence" in aliased.err

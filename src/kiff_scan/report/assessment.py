"""Render technical governability assessments."""

from __future__ import annotations

import html
import json

from .. import __version__
from ..assessment import GovernabilityAssessment
from ..model import Finding

__all__ = ["assessment_to_html", "assessment_to_json", "assessment_to_markdown"]


def _finding_payload(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "tool": finding.tool,
        "file": finding.file,
        "line": finding.line,
        "category": finding.category,
        "consequence": finding.consequence.label,
        "severity": finding.severity,
        "state_dependent": finding.state_dependent,
        "annotation_mismatch": finding.annotation_mismatch,
        "declared_annotations": finding.annotations,
        "reason": finding.reason,
        "reachable_by": finding.reachable_by,
        "model_controlled_inputs": finding.inputs,
        "confidence": finding.confidence,
        "governed": finding.governed,
        "decision_evidence": {
            "kind": finding.evidence.kind.value,
            "detail": finding.evidence.detail,
            "line": finding.evidence.line,
        },
        "action": finding.action,
        "fixed_program": finding.fixed_program,
        "in_test_code": finding.in_test_code,
    }


def assessment_payload(assessment: GovernabilityAssessment) -> dict:
    """Stable, versioned representation with evidence separate from conclusions."""
    result = assessment.scan
    return {
        "schema_version": assessment.schema_version,
        "report_type": "kiff_agent_governability_assessment",
        "tool": {"name": "kiff-scan", "version": __version__},
        "metadata": {
            "generated_at": assessment.generated_at,
            "root": assessment.root,
            "repository_commit": assessment.repository_commit,
            "files_analysed": result.files,
            "unsupported_files": len(result.unsupported),
            "include_tests": result.include_tests,
            "languages": {"supported": ["Python"], "unsupported_detected": len(result.unsupported)},
        },
        "conclusion": {
            "readiness": assessment.readiness.value,
            "label": assessment.readiness.label,
            "reason": assessment.readiness_reason,
            "hard_blocker_count": len(assessment.blockers),
        },
        "dimensions": [
            {
                "id": dimension.id,
                "title": dimension.title,
                "evidence_state": dimension.state.value,
                "summary": dimension.summary,
                "evidence": list(dimension.evidence),
            }
            for dimension in assessment.dimensions
        ],
        "hard_blockers": [
            {
                "code": blocker.code,
                "title": blocker.title,
                "detail": blocker.detail,
                "location": {
                    "file": blocker.file,
                    "line": blocker.line,
                    "tool": blocker.tool,
                },
            }
            for blocker in assessment.blockers
        ],
        "remediation": [
            {
                "priority": item.priority,
                "title": item.title,
                "detail": item.detail,
                "locations": list(item.locations),
            }
            for item in assessment.remediations
        ],
        "evidence": {
            "summary": {
                "consequential_capabilities": len(result.scored),
                "decision_found": len(result.governed),
                "review_required": len(result.ungoverned),
                "by_severity": result.counts_by_severity(),
                "test_code_findings_set_aside": len(result.test_code),
                "kiff_boundary_detected": result.kiff_present,
            },
            "actions": [_finding_payload(finding) for finding in result.scored],
            "unsupported": [{"file": item.path, "why": item.why} for item in result.unsupported],
        },
        "claim_boundary": [
            "This is a static, code-level governability assessment, "
            "not a compliance certification.",
            "A clean scan does not prove that an agent is safe or production-ready.",
            "The report does not establish runtime behavior, external reachability, "
            "live-state correctness, organizational controls, or regulatory compliance.",
            "Evidence marked not_assessable was not converted into a pass or failure.",
        ],
    }


def assessment_to_json(assessment: GovernabilityAssessment) -> str:
    return json.dumps(assessment_payload(assessment), indent=2) + "\n"


def assessment_to_markdown(assessment: GovernabilityAssessment) -> str:
    result = assessment.scan
    lines = [
        "# Agent Governability Evidence",
        "",
        f"**Result: {assessment.readiness.label}**",
        "",
        assessment.readiness_reason,
        "",
        "## Executive summary",
        "",
        f"- Consequential capabilities identified: **{len(result.scored)}**",
        f"- Pre-execution decisions evidenced: **{len(result.governed)}**",
        f"- Capabilities requiring review: **{len(result.ungoverned)}**",
        f"- Hard blockers: **{len(assessment.blockers)}**",
        f"- Supported files analyzed: **{result.files}**",
        f"- Unsupported files: **{len(result.unsupported)}**",
        "",
    ]

    if assessment.blockers:
        lines.extend(["## Hard blockers", ""])
        for blocker in assessment.blockers:
            lines.append(
                f"- **{blocker.title}** — `{blocker.file}:{blocker.line}` "
                f"`{blocker.tool}()` — {blocker.detail}"
            )
        lines.append("")

    lines.extend(
        [
            "## Governability scorecard",
            "",
            "| Dimension | Evidence state | Conclusion |",
            "|---|---|---|",
        ]
    )
    for dimension in assessment.dimensions:
        lines.append(
            f"| {dimension.title} | **{dimension.state.value.replace('_', ' ')}** | "
            f"{dimension.summary} |"
        )
    lines.append("")

    lines.extend(["## Consequential-action register", ""])
    if result.scored:
        lines.extend(
            [
                "| Tool | Location | Consequence | Severity | Decision evidence | "
                "State-dependent |",
                "|---|---|---|---|---|---|",
            ]
        )
        for finding in result.scored:
            lines.append(
                f"| `{finding.tool}()` | `{finding.file}:{finding.line}` | "
                f"{finding.consequence.label} | {finding.severity} | "
                f"{finding.evidence.kind.value} | {'yes' if finding.state_dependent else 'no'} |"
            )
    else:
        lines.append(
            "No consequential model-reachable action was identified in the supported scope."
        )
    lines.append("")

    lines.extend(["## Evidence paths", ""])
    for finding in result.scored:
        lines.extend(
            [
                f"### `{finding.tool}()`",
                "",
                f"- Entry point: {finding.reachable_by}",
                f"- Consequence: {finding.reason}",
                f"- Decision: {finding.evidence.detail}",
                f"- Match confidence: {finding.confidence}",
                "",
            ]
        )
    if not result.scored:
        lines.extend(["No evidence path was produced.", ""])

    weak = [
        finding
        for finding in result.scored
        if finding.annotation_mismatch
        or finding.confidence != "call"
        or finding.evidence.kind.value in ("module_hook", "call_after_sink")
    ]
    lines.extend(["## Contradictions and weak evidence", ""])
    if weak:
        for finding in weak:
            reasons: list[str] = []
            if finding.annotation_mismatch:
                reasons.append("declared read-only but reaches a consequential call")
            if finding.confidence != "call":
                reasons.append(f"{finding.confidence} match confidence")
            if finding.evidence.kind.value == "module_hook":
                reasons.append("module-level decision evidence is coarse")
            if finding.evidence.kind.value == "call_after_sink":
                reasons.append("decision appears after the consequence")
            lines.append(
                f"- `{finding.file}:{finding.line}` `{finding.tool}()` — {'; '.join(reasons)}"
            )
    else:
        lines.append("No contradiction or explicitly weak evidence was identified.")
    lines.append("")

    lines.extend(["## Prioritized remediation", ""])
    if assessment.remediations:
        for item in assessment.remediations:
            lines.append(f"{item.priority}. **{item.title}.** {item.detail}")
    else:
        lines.append("No code-level remediation was derived from the available evidence.")
    lines.append("")

    lines.extend(
        [
            "## Scope and claim boundary",
            "",
            "This is a static, code-level governability assessment, not a compliance "
            "certification.",
            "A clean scan does not prove that an agent is safe or production-ready. "
            "Runtime behavior,",
            "external reachability, live-state correctness, organizational controls, "
            "model quality,",
            "and regulatory compliance are outside this report's evidence boundary.",
            "",
            "## Reproducibility",
            "",
            f"- kiff-scan: `{__version__}`",
            f"- Assessment schema: `{assessment.schema_version}`",
            f"- Generated: `{assessment.generated_at}`",
            f"- Root: `{assessment.root}`",
            f"- Repository commit: `{assessment.repository_commit or 'not available'}`",
            f"- Include test/example findings: `{str(result.include_tests).lower()}`",
            "",
        ]
    )
    return "\n".join(lines)


def assessment_to_html(assessment: GovernabilityAssessment) -> str:
    """Self-contained management report; no scripts, fonts, or remote assets."""
    result = assessment.scan

    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    dimension_rows = "".join(
        "<tr>"
        f"<td><strong>{esc(d.title)}</strong></td>"
        f'<td><span class="status {esc(d.state.value)}">'
        f"{esc(d.state.value.replace('_', ' '))}</span></td>"
        f"<td>{esc(d.summary)}</td>"
        "</tr>"
        for d in assessment.dimensions
    )
    blocker_rows = (
        "".join(
            "<li>"
            f"<strong>{esc(b.title)}</strong> "
            f"<code>{esc(b.file)}:{b.line}</code><br>{esc(b.detail)}"
            "</li>"
            for b in assessment.blockers
        )
        or "<li>No hard blocker identified in the supported scope.</li>"
    )
    action_rows = (
        "".join(
            "<tr>"
            f"<td><code>{esc(f.tool)}()</code><small>{esc(f.file)}:{f.line}</small></td>"
            f"<td>{esc(f.consequence.label)}</td>"
            f'<td><span class="severity {esc(f.severity)}">{esc(f.severity)}</span></td>'
            f"<td>{esc(f.evidence.kind.value.replace('_', ' '))}"
            f"<small>{esc(f.evidence.detail)}</small></td>"
            "</tr>"
            for f in result.scored
        )
        or '<tr><td colspan="4">No consequential action identified '
        "in the supported scope.</td></tr>"
    )
    remediation = (
        "".join(
            f"<li><strong>{esc(item.title)}</strong><br>{esc(item.detail)}</li>"
            for item in assessment.remediations
        )
        or "<li>No code-level remediation derived from the available evidence.</li>"
    )
    evidence_paths = (
        "".join(
            "<li>"
            f"<strong>{esc(f.tool)}()</strong> — {esc(f.reachable_by)} → "
            f"{esc(f.reason)}<small>Decision: {esc(f.evidence.detail)} · "
            f"confidence: {esc(f.confidence)}</small>"
            "</li>"
            for f in result.scored
        )
        or "<li>No evidence path was produced.</li>"
    )
    weak_findings = [
        finding
        for finding in result.scored
        if finding.annotation_mismatch
        or finding.confidence != "call"
        or finding.evidence.kind.value in ("module_hook", "call_after_sink")
    ]
    weak = (
        "".join(
            "<li>"
            f"<code>{esc(f.file)}:{f.line}</code> <strong>{esc(f.tool)}()</strong> — "
            f"confidence: {esc(f.confidence)}; decision evidence: {esc(f.evidence.kind.value)}"
            "</li>"
            for f in weak_findings
        )
        or "<li>No contradiction or explicitly weak evidence was identified.</li>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Governability Evidence</title>
<style>
:root{{--ink:#171a1f;--muted:#5d6570;--line:#d9dde3;--paper:#fff;--wash:#f4f6f8;
--red:#a62b2b;--amber:#8a5a00;--green:#206a44}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--wash);color:var(--ink);font:15px/1.55 system-ui,
-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}}
main{{max-width:1120px;margin:0 auto;background:var(--paper);min-height:100vh;padding:56px 64px}}
h1{{font-size:34px;line-height:1.15;margin:0 0 12px}}
h2{{font-size:20px;margin:42px 0 14px;border-bottom:1px solid var(--line);padding-bottom:9px}}
p{{max-width:78ch}}
.eyebrow{{font-size:12px;font-weight:700;text-transform:uppercase;color:var(--muted)}}
.result{{font-size:22px;font-weight:750;margin:10px 0 4px}}
.result.not_ready{{color:var(--red)}}
.result.conditional{{color:var(--amber)}}
.result.ready_within_scanned_scope{{color:var(--green)}}
.metrics{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:1px;
background:var(--line);border:1px solid var(--line);margin:30px 0}}
.metric{{background:#fff;padding:18px}}
.metric strong{{display:block;font-size:25px}}
.metric span,small{{display:block;color:var(--muted);font-size:12px}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:12px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}}
th{{font-size:12px;color:var(--muted);text-transform:uppercase}}
.status,.severity{{display:inline-block;padding:2px 7px;border-radius:3px;
font-size:12px;font-weight:700}}
.not_evidenced,.not_ready,.high{{background:#fbe9e9;color:var(--red)}}
.partial,.not_assessable,.conditional,.medium{{background:#fff4d6;color:var(--amber)}}
.evidenced,.ready_within_scanned_scope{{background:#e7f5ed;color:var(--green)}}
.low{{background:#edf1f5;color:#46515e}}
code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}}
ol,ul{{padding-left:22px}}
li{{margin:9px 0}}
.boundary{{border-left:3px solid var(--ink);padding:2px 0 2px 16px;color:var(--muted)}}
footer{{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);
font-size:12px;color:var(--muted)}}
@media(max-width:760px){{main{{padding:32px 20px}}
.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}
table{{display:block;overflow-x:auto}}}}
</style>
</head>
<body><main>
<div class="eyebrow">KIFF technical governance report</div>
<h1>Agent Governability Evidence</h1>
<div class="result {esc(assessment.readiness.value)}">{esc(assessment.readiness.label)}</div>
<p>{esc(assessment.readiness_reason)}</p>
<section class="metrics">
<div class="metric"><strong>{len(result.scored)}</strong>
<span>Consequential capabilities</span></div>
<div class="metric"><strong>{len(result.governed)}</strong><span>Decisions evidenced</span></div>
<div class="metric"><strong>{len(result.ungoverned)}</strong><span>Require review</span></div>
<div class="metric"><strong>{len(assessment.blockers)}</strong><span>Hard blockers</span></div>
<div class="metric"><strong>{result.files}</strong><span>Files analyzed</span></div>
</section>
<h2>Hard blockers</h2><ul>{blocker_rows}</ul>
<h2>Governability scorecard</h2>
<table><thead><tr><th>Dimension</th><th>Evidence</th><th>Conclusion</th></tr></thead>
<tbody>{dimension_rows}</tbody></table>
<h2>Consequential-action register</h2>
<table><thead><tr><th>Tool and location</th><th>Consequence</th><th>Severity</th>
<th>Decision evidence</th></tr></thead><tbody>{action_rows}</tbody></table>
<h2>Evidence paths</h2><ul>{evidence_paths}</ul>
<h2>Contradictions and weak evidence</h2><ul>{weak}</ul>
<h2>Prioritized remediation</h2><ol>{remediation}</ol>
<h2>Scope and claim boundary</h2>
<p class="boundary">This is a static, code-level governability assessment, not a compliance
certification. A clean scan does not prove that an agent is safe or production-ready.
Runtime behavior, live-state correctness, organizational controls, model quality, and
regulatory compliance are outside this report's evidence boundary.</p>
<footer>kiff-scan {esc(__version__)} · schema {assessment.schema_version} ·
generated {esc(assessment.generated_at)} ·
commit {esc(assessment.repository_commit or "not available")}</footer>
</main></body></html>\n"""

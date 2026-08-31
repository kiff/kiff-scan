"""Machine-readable reports."""

from __future__ import annotations

import json

from ..model import ScanResult

__all__ = ["to_json", "to_markdown"]

SCHEMA_VERSION = 1


def to_json(result: ScanResult, root: str = ".") -> str:
    """Stable JSON. `schema_version` is bumped on any breaking shape change.

    Contains file paths, line numbers, and parameter *names*. It deliberately
    contains no source text and no argument values, so a report can be shared
    without shipping code or secrets along with it.
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "kiff-scan", "version": _version()},
        "root": root,
        "summary": {
            "files_analysed": result.files,
            "capabilities": len(result.findings),
            "decision_found": len(result.governed),
            "review_required": len(result.ungoverned),
            "by_severity": result.counts_by_severity(),
            "unsupported_files": len(result.unsupported),
            "kiff_present": result.kiff_present,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "tool": f.tool,
                "file": f.file,
                "line": f.line,
                "category": f.category,
                "consequence": f.consequence.label,
                "severity": f.severity,
                "state_dependent": f.state_dependent,
                "reason": f.reason,
                "reachable_by": f.reachable_by,
                "model_controlled_inputs": f.inputs,
                "confidence": f.confidence,
                "governed": f.governed,
                "decision_evidence": {
                    "kind": f.evidence.kind.value,
                    "detail": f.evidence.detail,
                    "line": f.evidence.line,
                },
                "action": f.action,
            }
            for f in result.findings
        ],
        "unsupported": [{"file": u.path, "why": u.why} for u in result.unsupported],
        "not_established": [
            "external reachability of the action",
            "absence of a guard outside the analysed path",
            "practical exploitability",
            "that any finding is a vulnerability",
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(result: ScanResult, root: str = ".") -> str:
    """Markdown summary, for a PR comment or an issue."""
    counts = result.counts_by_severity()
    lines = [
        "## kiff-scan: agent blast radius",
        "",
        f"- Consequential capabilities: **{len(result.findings)}**",
        f"- Decision found on path: **{len(result.governed)}**",
        f"- Review required: **{len(result.ungoverned)}** "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)",
        f"- Files analysed: {result.files}",
    ]
    if result.unsupported:
        lines.append(f"- Not analysed (never counted as clean): {len(result.unsupported)}")
    lines.append("")

    if result.ungoverned:
        lines += [
            "| Action | Location | Consequence | Severity | State-dependent | Confidence |",
            "|---|---|---|---|---|---|",
        ]
        for f in result.ungoverned:
            lines.append(
                f"| `{f.tool}()` | `{f.file}:{f.line}` | {f.consequence.label} | "
                f"{f.severity} | {'yes' if f.state_dependent else 'no'} | {f.confidence} |"
            )
        lines.append("")

    if result.governed:
        lines.append("<details><summary>Cleared, with evidence</summary>")
        lines.append("")
        for f in result.governed:
            lines.append(f"- `{f.tool}()` — {f.evidence.detail}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines += [
        "> **What this did not establish:** external reachability, the absence of a",
        "> guard outside the analysed path, practical exploitability, or that any",
        "> finding is a vulnerability. A clean scan means no supported path was",
        "> identified — not that the code is safe.",
    ]
    return "\n".join(lines) + "\n"


def _version() -> str:
    from .. import __version__

    return __version__

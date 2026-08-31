"""Human-readable terminal report.

Design rules, learned from tools that get ignored:

  - Lead with the shape of the exposure, not a wall of findings.
  - Name the single most exposed call site, because that is what gets fixed.
  - Print the evidence for every verdict, including the cleared ones, so the
    reader can disagree with the scanner.
  - Always print what the scan did NOT establish. A report that omits its own
    limits invites the false confidence this tool exists to remove.
"""

from __future__ import annotations

import os

from ..model import DecisionEvidence, Finding, ScanResult

__all__ = ["render", "render_explain"]

_LIMITS = (
    "This scan established that a model-controlled parameter reaches a",
    "consequential call with no recognised decision on the analysed path.",
    "It did NOT establish that the action is externally reachable, that no",
    "guard exists elsewhere, that exploitation is practical, or that any",
    "finding is a vulnerability. A clean scan means no supported path was",
    "identified -- not that the code is safe.",
)


def _rel(path: str, root: str) -> str:
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
    try:
        return os.path.relpath(path, base or ".")
    except ValueError:  # pragma: no cover - different drives on Windows
        return path


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _wrap(text: str, indent: str, width: int = 76) -> list[str]:
    """Wrap prose to `width`, prefixing each line with `indent`.

    Hand-rolled rather than using textwrap so the reporter keeps its exact
    layout, and so this module has no import beyond `os`.
    """
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width - len(indent) and current:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines


def _most_exposed(findings: list[Finding]) -> Finding:
    """Worst finding: highest severity, then a proven call over an inference."""
    return max(
        findings,
        key=lambda f: (
            f.severity == "high",
            f.confidence == "call",
            f.state_dependent,
        ),
    )


def render(result: ScanResult, root: str) -> str:
    out: list[str] = []
    ungoverned = result.ungoverned
    governed = result.governed

    out.append("")
    out.append("  YOUR AGENT'S BLAST RADIUS")
    out.append("")
    out.append(f"  Consequential capabilities: {len(result.findings)}")
    out.append(f"    Decision found on path:   {len(governed)}")
    out.append(f"    Review required:          {len(ungoverned)}")
    out.append("")

    if ungoverned:
        out.append(
            f"  Your agent can reach {_plural(len(ungoverned), 'consequential action')} " "with no"
        )
        out.append("  recognised decision on the path.")
        out.append("")

        by_category: dict[str, list[Finding]] = {}
        for f in ungoverned:
            by_category.setdefault(f.category, []).append(f)

        for _category, items in sorted(by_category.items(), key=lambda kv: -len(kv[1])):
            label = items[0].consequence.label
            names = ", ".join(sorted({i.tool for i in items}))
            out.append(f"    {label:<20} {len(items):>2}   {names}")
        out.append("")

        worst = _most_exposed(ungoverned)
        out.append(f"  Most exposed: {_rel(worst.file, root)}:{worst.line}  {worst.tool}()")
        out.append(f"    Reachable by:            {worst.reachable_by}")
        out.append(f"    Consequence:             {worst.consequence.label}  ({worst.reason})")
        out.append(f"    Severity:                {worst.severity}")
        out.append(f"    Match confidence:        {worst.confidence}")
        out.append(f"    Decision on path:        {worst.evidence.detail}")
        out.append(f"    Model-controlled inputs: {', '.join(worst.inputs) or '-'}")
        if worst.state_dependent:
            out.append("")
            out.append("    State-dependent: an authorization check is necessary but NOT")
            out.append("    sufficient here.")
            out.extend(_wrap(worst.consequence.why, "    "))
        out.append("")

        after = [f for f in ungoverned if f.evidence.kind is DecisionEvidence.CALL_AFTER_SINK]
        if after:
            out.append(f"  {_plural(len(after), 'action')} has a guard call that runs *after* the")
            out.append("  consequential call, so it cannot have gated it:")
            for f in after:
                out.append(f"    ! {f.tool:<20} {f.evidence.detail}")
            out.append("")

    if governed:
        out.append(f"  {_plural(len(governed), 'action')} cleared, with evidence:")
        for f in sorted(governed, key=lambda f: f.tool):
            label = f.action or f.category
            out.append(f"    ok {f.tool:<20} {label:<18} {f.evidence.detail}")
        out.append("")

        coarse = [f for f in governed if f.evidence.kind is DecisionEvidence.MODULE_HOOK]
        if coarse:
            out.append(f"  Note: {_plural(len(coarse), 'action')} cleared by a module-level hook,")
            out.append("  which is coarser than a per-call proof. The hook governs every tool")
            out.append("  on the agent, so confirm it is mounted in enforce mode.")
            out.append("")

        state_dep = sorted({f.action or f.tool for f in governed if f.state_dependent})
        if state_dep:
            out.append("  State-dependent actions -- for these, an authorization check or a")
            out.append("  signed plan is not enough. They are legitimate in one state and")
            out.append("  catastrophic in another, so only a decision evaluated against live")
            out.append("  state can refuse them at the wrong moment:")
            out.append("    " + ", ".join(state_dep))
            out.append("")

    if not result.findings:
        out.append("  No agent-reachable consequential actions found in the analysed path.")
        out.append("")

    counts = result.counts_by_severity()
    out.append(
        f"  {_plural(len(result.findings), 'finding')} in "
        f"{_plural(result.files, 'file')}"
        f"  (review required: {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low)"
    )

    if result.unsupported:
        n = len(result.unsupported)
        verb = "was" if n == 1 else "were"
        out.append(f"  {_plural(n, 'file')} could not be analysed and {verb} NOT counted as clean.")
        out.append("  Run with --show-unsupported to list them.")

    out.append("")
    out.append("  What this scan did not establish:")
    for line in _LIMITS:
        out.append(f"    {line}")
    out.append("")

    if ungoverned:
        out.append("  Next:")
        first = _most_exposed(ungoverned)
        out.append(f"    kiff-scan explain {_rel(first.file, root)}:{first.line}")
        out.append("")

    return "\n".join(out)


def render_explain(finding: Finding, root: str) -> str:
    """Full analysed path for one finding."""
    out: list[str] = []
    out.append("")
    out.append(f"  {_rel(finding.file, root)}:{finding.line}  {finding.tool}()")
    out.append("")
    out.append(f"  1. Agent entry point      {finding.reachable_by}")
    out.append(f"  2. Model-controlled input {', '.join(finding.inputs) or '-'}")
    out.append(f"  3. Consequential call     {finding.reason}")
    out.append(f"  4. Consequence category   {finding.category} ({finding.consequence.label})")
    out.append(f"  5. Severity               {finding.severity}")
    out.append(f"  6. Match confidence       {finding.confidence}")
    out.append(f"  7. Decision on path       {finding.evidence.detail}")
    out.append("")

    if finding.state_dependent:
        out.append("  Why an authorization check is not sufficient here:")
        out.extend(_wrap(finding.consequence.why, "    "))
        out.append("")
        out.append("  This action can be fully authorized, requested by a legitimate")
        out.append("  principal, and still wrong -- because its safety depends on live")
        out.append("  state at the moment of execution. A decision evaluated against that")
        out.append("  state is what refuses it; a role check cannot.")
        out.append("")
    else:
        out.append("  This category is not state-dependent: an authorization check plus")
        out.append("  strict input handling addresses it.")
        out.append("")

    if finding.confidence == "declared":
        out.append("  Note: classified from the function's name and docstring, not from an")
        out.append("  observed SDK call. Verify before acting on it.")
        out.append("")

    out.append("  What this does not establish:")
    for line in _LIMITS:
        out.append(f"    {line}")
    out.append("")
    return "\n".join(out)

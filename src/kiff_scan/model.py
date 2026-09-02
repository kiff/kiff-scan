"""Data model for a scan.

The important type here is `DecisionEvidence`. An earlier prototype of this
scanner recorded governance as a single boolean computed per *file*: if any
guard-ish string appeared anywhere in the source, every agent-reachable action
in that file was reported as governed. That is unsound in the worst possible
direction for a security tool -- one governed function silently vouches for its
unguarded neighbours, and the scan reports clean on code that is not.

So governance is never a bare boolean here. Every finding carries the specific
evidence that justified the verdict, at a named precision level, and the
reporters print it. A reader can then judge the verdict instead of trusting it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .taxonomy import CONSEQUENCES, Consequence

__all__ = ["DecisionEvidence", "Evidence", "Finding", "ScanResult", "UnsupportedFile"]


class DecisionEvidence(str, Enum):
    """How (and how precisely) a decision boundary was established for a sink.

    Ordered from strongest to weakest. `NONE` is the only value that produces a
    finding; the others explain why a candidate was cleared.
    """

    #: A decision/guard call appears in the same function body, lexically
    #: before the sink. The most precise signal available to a v1 analyser.
    CALL_BEFORE_SINK = "call_before_sink"

    #: A decision/guard call is in the same function body but only *after* the
    #: sink. Reported as a finding: it cannot have gated what already ran.
    CALL_AFTER_SINK = "call_after_sink"

    #: A recognised guard decorator wraps the function containing the sink.
    DECORATOR = "decorator"

    #: A module-level hook installs a guard over every tool on the agent
    #: (for example a tool-hooks list wired at agent construction). This is a
    #: genuine whole-module signal, unlike a stray call in one function.
    MODULE_HOOK = "module_hook"

    #: The framework's own human-in-the-loop flag is set on the tool
    #: decorator -- `requires_confirmation=True`, `needs_approval=True`. The
    #: framework will not run the tool without a human, which is a decision
    #: boundary expressed in the framework's vocabulary rather than ours.
    FRAMEWORK_APPROVAL = "framework_approval"

    #: Nothing found on the analysed path.
    NONE = "none"


@dataclass(frozen=True)
class Evidence:
    """A single piece of located evidence."""

    kind: DecisionEvidence
    detail: str
    line: int = 0

    @property
    def governs(self) -> bool:
        """Whether this evidence actually gates the sink.

        A call placed after the sink is evidence of intent, not of control.
        """
        return self.kind in (
            DecisionEvidence.CALL_BEFORE_SINK,
            DecisionEvidence.DECORATOR,
            DecisionEvidence.MODULE_HOOK,
            DecisionEvidence.FRAMEWORK_APPROVAL,
        )


@dataclass
class Finding:
    """One agent-reachable consequential action."""

    tool: str
    file: str
    line: int
    category: str
    #: How the sink was recognised, e.g. "calls delete_db_instance()".
    reason: str
    #: How the function is reachable by the model, e.g. "@tool".
    reachable_by: str
    #: Parameter *names* from the signature. Never argument values -- a scan
    #: report must not become a place where literals from source are copied.
    inputs: list[str]
    evidence: Evidence
    #: Confidence in the sink match: "call" (a real SDK call was found) or
    #: "declared" (inferred from the tool's name/docstring only).
    confidence: str = "call"
    #: Resolved domain action name, when the codebase declares one.
    action: str = ""
    #: The tool declares `readOnlyHint=True` and yet reaches a consequential
    #: call. Reported separately: the tool's own metadata is the accuser.
    annotation_mismatch: bool = False
    #: MCP ToolAnnotations declared on the tool decorator, as written.
    annotations: dict = field(default_factory=dict)

    @property
    def consequence(self) -> Consequence:
        return CONSEQUENCES[self.category]

    @property
    def severity(self) -> str:
        sev = self.consequence.severity
        # A name/docstring inference is weaker proof than an observed call, so
        # it is never allowed to raise a build failure at "high".
        if self.confidence in ("declared", "annotated") and sev == "high":
            return "medium"
        return sev

    @property
    def governed(self) -> bool:
        return self.evidence.governs

    @property
    def state_dependent(self) -> bool:
        return self.consequence.state_dependent

    @property
    def rule_id(self) -> str:
        return f"KIFF-{self.category.replace('_', '-')}"


@dataclass(frozen=True)
class UnsupportedFile:
    """A file that was seen but could not be analysed.

    Tracked explicitly and reported. A file the scanner cannot parse must never
    be silently counted as clean -- that is how a scanner produces false
    assurance.
    """

    path: str
    why: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files: int = 0
    unsupported: list[UnsupportedFile] = field(default_factory=list)
    #: True when a KIFF decision boundary was detected anywhere in the tree.
    kiff_present: bool = False

    @property
    def ungoverned(self) -> list[Finding]:
        return [f for f in self.findings if not f.governed]

    @property
    def governed(self) -> list[Finding]:
        return [f for f in self.findings if f.governed]

    def counts_by_severity(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        for f in self.ungoverned:
            if f.severity in out:
                out[f.severity] += 1
        return out

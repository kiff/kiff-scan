"""Evidence-backed technical governability assessment.

The assessment derives conclusions from a :class:`ScanResult`; it does not run
another detector pass.  This separation matters: reports may explain scanner
evidence, but must not manufacture governance evidence that the analyzer did
not establish.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .model import DecisionEvidence, ScanResult

__all__ = [
    "AssessmentBlocker",
    "AssessmentDimension",
    "EvidenceState",
    "GovernabilityAssessment",
    "Readiness",
    "Remediation",
    "assess",
]

ASSESSMENT_SCHEMA_VERSION = 1


class EvidenceState(str, Enum):
    EVIDENCED = "evidenced"
    PARTIAL = "partial"
    NOT_EVIDENCED = "not_evidenced"
    NOT_ASSESSABLE = "not_assessable"


class Readiness(str, Enum):
    NOT_READY = "not_ready"
    CONDITIONAL = "conditional"
    READY_WITHIN_SCANNED_SCOPE = "ready_within_scanned_scope"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").upper()


@dataclass(frozen=True)
class AssessmentDimension:
    id: str
    title: str
    state: EvidenceState
    summary: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssessmentBlocker:
    code: str
    title: str
    detail: str
    file: str
    line: int
    tool: str


@dataclass(frozen=True)
class Remediation:
    priority: int
    title: str
    detail: str
    locations: tuple[str, ...] = ()


@dataclass
class GovernabilityAssessment:
    root: str
    generated_at: str
    repository_commit: str | None
    scan: ScanResult
    readiness: Readiness
    readiness_reason: str
    dimensions: list[AssessmentDimension] = field(default_factory=list)
    blockers: list[AssessmentBlocker] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)
    schema_version: int = ASSESSMENT_SCHEMA_VERSION


def _dimension_inventory(result: ScanResult) -> AssessmentDimension:
    capabilities = len(result.scored)
    evidence = (
        f"{result.files} supported Python files parsed",
        f"{capabilities} consequential model-reachable capabilities identified",
    )
    if result.files == 0:
        return AssessmentDimension(
            "action_inventory",
            "Consequential action inventory",
            EvidenceState.NOT_ASSESSABLE,
            "No supported source file was successfully analyzed.",
            evidence,
        )
    if result.unsupported:
        return AssessmentDimension(
            "action_inventory",
            "Consequential action inventory",
            EvidenceState.PARTIAL,
            "The Python inventory is available, but unsupported files prevent "
            "a repository-wide conclusion.",
            evidence + (f"{len(result.unsupported)} files were not analyzed",),
        )
    return AssessmentDimension(
        "action_inventory",
        "Consequential action inventory",
        EvidenceState.EVIDENCED,
        "Supported source files were analyzed and consequential model-reachable "
        "paths were inventoried.",
        evidence,
    )


def _dimension_decisions(result: ScanResult) -> AssessmentDimension:
    total = len(result.scored)
    governed = len(result.governed)
    if not total:
        return AssessmentDimension(
            "decision_coverage",
            "Pre-execution decision coverage",
            EvidenceState.NOT_ASSESSABLE,
            "No consequential capability was identified, so decision coverage could not be tested.",
        )
    evidence = (
        f"{governed} of {total} capabilities have recognized pre-execution decision evidence",
        f"{len(result.ungoverned)} require review",
    )
    if governed == total:
        state = EvidenceState.EVIDENCED
        summary = (
            "Every identified consequential path has recognized decision evidence before execution."
        )
    elif governed:
        state = EvidenceState.PARTIAL
        summary = "Decision evidence exists on some, but not all, consequential paths."
    else:
        state = EvidenceState.NOT_EVIDENCED
        summary = "No identified consequential path has recognized pre-execution decision evidence."
    return AssessmentDimension(
        "decision_coverage", "Pre-execution decision coverage", state, summary, evidence
    )


def _dimension_state(result: ScanResult) -> AssessmentDimension:
    state_dependent = [f for f in result.scored if f.state_dependent]
    if not state_dependent:
        return AssessmentDimension(
            "operational_state",
            "Operational-state grounding",
            EvidenceState.NOT_ASSESSABLE,
            "No state-dependent consequential path was identified in the scanned scope.",
        )
    return AssessmentDimension(
        "operational_state",
        "Operational-state grounding",
        EvidenceState.NOT_ASSESSABLE,
        "State-dependent actions were identified, but the current static analysis "
        "cannot prove that decisions use live operational state.",
        (f"{len(state_dependent)} capabilities are state-dependent",),
    )


def _dimension_human_authority(result: ScanResult) -> AssessmentDimension:
    total = len(result.scored)
    if not total:
        return AssessmentDimension(
            "human_authority",
            "Human authority",
            EvidenceState.NOT_ASSESSABLE,
            "No consequential capability was identified in the scanned scope.",
        )
    approved = [f for f in result.scored if f.evidence.kind is DecisionEvidence.FRAMEWORK_APPROVAL]
    if not approved:
        return AssessmentDimension(
            "human_authority",
            "Human authority",
            EvidenceState.NOT_EVIDENCED,
            "No explicit framework-enforced human approval was identified. Generic "
            "guards are not treated as proof of independent approval.",
        )
    if len(approved) == total:
        state = EvidenceState.EVIDENCED
        summary = "Every identified capability declares framework-enforced human approval."
    else:
        state = EvidenceState.PARTIAL
        summary = "Explicit human approval is evidenced for only part of the consequential surface."
    return AssessmentDimension(
        "human_authority",
        "Human authority",
        state,
        summary,
        (f"{len(approved)} of {total} capabilities declare framework approval",),
    )


def _unassessable_dimension(id: str, title: str, total: int, summary: str) -> AssessmentDimension:
    suffix = (
        f"{total} consequential capabilities are in scope, but this evidence is "
        "not currently classified."
        if total
        else "No consequential capability was identified in the scanned scope."
    )
    return AssessmentDimension(id, title, EvidenceState.NOT_ASSESSABLE, summary, (suffix,))


def _dimensions(result: ScanResult) -> list[AssessmentDimension]:
    total = len(result.scored)
    return [
        _dimension_inventory(result),
        _dimension_decisions(result),
        _dimension_state(result),
        _dimension_human_authority(result),
        _unassessable_dimension(
            "identity_permissions",
            "Identity and permission boundaries",
            total,
            "The scanner recognizes decision calls by shape and name; it does not "
            "prove which actor identity or permissions the runtime derives.",
        ),
        _unassessable_dimension(
            "traceability",
            "Traceability",
            total,
            "The scanner does not currently establish durable decisions, receipts, "
            "event records, or execution outcomes.",
        ),
    ]


def _blockers(result: ScanResult) -> list[AssessmentBlocker]:
    blockers: list[AssessmentBlocker] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in result.scored:
        key = (finding.file, finding.line, finding.tool)
        if finding.annotation_mismatch:
            blockers.append(
                AssessmentBlocker(
                    "contradictory_annotation",
                    "Consequential tool is declared read-only",
                    f"{finding.reason}; the tool declares readOnlyHint=True.",
                    finding.file,
                    finding.line,
                    finding.tool,
                )
            )
            seen.add(key)
        if not finding.governed and finding.severity == "high" and key not in seen:
            blockers.append(
                AssessmentBlocker(
                    "high_consequence_without_decision",
                    "High-consequence path has no pre-execution decision",
                    f"{finding.consequence.label}: {finding.reason}. {finding.evidence.detail}.",
                    finding.file,
                    finding.line,
                    finding.tool,
                )
            )
    return blockers


def _remediations(result: ScanResult, blockers: list[AssessmentBlocker]) -> list[Remediation]:
    items: list[Remediation] = []
    if blockers:
        locations = tuple(f"{b.file}:{b.line}" for b in blockers)
        items.append(
            Remediation(
                1,
                "Close hard blockers before production",
                "Put a decision capable of refusal before each high-consequence call "
                "and correct contradictory tool annotations.",
                locations,
            )
        )

    remaining = [f for f in result.ungoverned if f.severity != "high"]
    if remaining:
        items.append(
            Remediation(
                2,
                "Review remaining undecided capabilities",
                "Decide whether each medium- or low-severity capability needs authorization, "
                "approval, input restriction, or removal.",
                tuple(f"{f.file}:{f.line}" for f in remaining),
            )
        )

    state_dependent = [f for f in result.scored if f.state_dependent]
    if state_dependent:
        items.append(
            Remediation(
                3,
                "Demonstrate live-state validation",
                "For state-dependent actions, record evidence that the pre-execution "
                "decision evaluates current entity or operational state; authorization "
                "alone is insufficient.",
                tuple(f"{f.file}:{f.line}" for f in state_dependent),
            )
        )

    if result.scored:
        items.append(
            Remediation(
                4,
                "Collect runtime identity and audit evidence",
                "Document how actor identity and permissions are derived, then retain "
                "durable decision and execution records. Static source evidence cannot "
                "establish these controls.",
            )
        )

    if result.unsupported:
        items.append(
            Remediation(
                5,
                "Assess unsupported source separately",
                "Unsupported files were not counted as clean. Review them manually "
                "or with a language-specific analyzer.",
                tuple(u.path for u in result.unsupported),
            )
        )
    return items


def _read_git_commit(root: str) -> str | None:
    """Read the current commit without invoking git or executing target code."""
    start = os.path.abspath(root if os.path.isdir(root) else os.path.dirname(root))
    current = start
    while True:
        marker = os.path.join(current, ".git")
        if os.path.isdir(marker):
            git_dir = marker
            break
        if os.path.isfile(marker):
            try:
                with open(marker, encoding="utf-8") as marker_file:
                    marker_text = marker_file.read().strip()
            except OSError:
                return None
            if not marker_text.startswith("gitdir: "):
                return None
            git_dir = marker_text[8:]
            if not os.path.isabs(git_dir):
                git_dir = os.path.normpath(os.path.join(current, git_dir))
            break
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent

    try:
        with open(os.path.join(git_dir, "HEAD"), encoding="utf-8") as head_file:
            head = head_file.read().strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head if len(head) == 40 else None

    ref = head[5:]
    try:
        with open(os.path.join(git_dir, ref), encoding="utf-8") as ref_file:
            value = ref_file.read().strip()
        return value if len(value) == 40 else None
    except OSError:
        pass
    try:
        packed_path = os.path.join(git_dir, "packed-refs")
        with open(packed_path, encoding="utf-8") as packed:
            for line in packed:
                if line.startswith(("#", "^")):
                    continue
                value, _, name = line.strip().partition(" ")
                if name == ref and len(value) == 40:
                    return value
    except OSError:
        return None
    return None


def assess(
    result: ScanResult,
    root: str = ".",
    *,
    generated_at: str | None = None,
    repository_commit: str | None = None,
) -> GovernabilityAssessment:
    """Derive a technical governability assessment from scanner evidence."""
    dimensions = _dimensions(result)
    blockers = _blockers(result)
    if blockers:
        readiness = Readiness.NOT_READY
        reason = f"{len(blockers)} hard blocker(s) require action before production."
    elif any(d.state is not EvidenceState.EVIDENCED for d in dimensions):
        readiness = Readiness.CONDITIONAL
        reason = (
            "No hard blocker was found, but important governance dimensions are partial, "
            "not evidenced, or not assessable from this scan."
        )
    else:
        readiness = Readiness.READY_WITHIN_SCANNED_SCOPE
        reason = "All required code-level checks are evidenced within the scanned scope."

    timestamp = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    commit = repository_commit if repository_commit is not None else _read_git_commit(root)
    return GovernabilityAssessment(
        root=root,
        generated_at=timestamp,
        repository_commit=commit,
        scan=result,
        readiness=readiness,
        readiness_reason=reason,
        dimensions=dimensions,
        blockers=blockers,
        remediations=_remediations(result, blockers),
    )

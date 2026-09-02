"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers.

Only governed=false findings become SARIF results. A cleared capability is
useful context in the terminal report but is not a code-scanning alert, and
emitting it as one would train people to ignore the Security tab.
"""

from __future__ import annotations

import json
import os

from ..model import ScanResult
from ..taxonomy import CONSEQUENCES

__all__ = ["to_sarif"]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: SARIF levels are error/warning/note/none.
_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _uri(path: str, root: str) -> str:
    """Repo-relative URI with forward slashes, as SARIF expects."""
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
    try:
        rel = os.path.relpath(path, base or ".")
    except ValueError:  # pragma: no cover - different drives on Windows
        rel = path
    return rel.replace(os.sep, "/")


def _rules() -> list[dict]:
    rules = []
    for cid, consequence in CONSEQUENCES.items():
        rule_id = f"KIFF-{cid.replace('_', '-')}"
        sd = (
            "This category is state-dependent: an authorization check is necessary "
            "but not sufficient, because the action's safety depends on live state "
            "at the moment of execution. "
            if consequence.state_dependent
            else ""
        )
        rules.append(
            {
                "id": rule_id,
                "name": f"AgentReachable{cid.title().replace('_', '')}",
                "shortDescription": {
                    "text": (
                        f"{consequence.label} reachable by an agent with no decision on the path"
                    )
                },
                "fullDescription": {"text": f"{sd}{consequence.why}"},
                "defaultConfiguration": {"level": _LEVEL.get(consequence.severity, "warning")},
                "properties": {
                    "category": cid,
                    "state_dependent": consequence.state_dependent,
                    "tags": ["agent", "authorization", "kiff-scan", cid.lower()],
                },
            }
        )
    return rules


def to_sarif(result: ScanResult, root: str = ".") -> str:
    from .. import __version__

    results = []
    for f in result.ungoverned:
        message = (
            f"{f.tool}() is reachable by the model ({f.reachable_by}) and "
            f"{f.reason}, with no recognised decision on the path "
            f"({f.evidence.detail}). "
            f"Model-controlled inputs: {', '.join(f.inputs) or 'none'}."
        )
        if f.state_dependent:
            message += (
                " This action is state-dependent, so an authorization check alone "
                "does not make it safe."
            )
        if f.confidence == "declared":
            message += (
                " Classified from the function name and docstring rather than an "
                "observed call; verify before acting."
            )

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(f.file, root)},
                            "region": {"startLine": max(f.line, 1)},
                        }
                    }
                ],
                "properties": {
                    "category": f.category,
                    "state_dependent": f.state_dependent,
                    "confidence": f.confidence,
                    "decision_evidence": f.evidence.kind.value,
                },
            }
        )

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kiff-scan",
                        "version": __version__,
                        "informationUri": "https://github.com/kiff/kiff-scan",
                        "rules": _rules(),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "files_analysed": result.files,
                            "unsupported_files": len(result.unsupported),
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2)

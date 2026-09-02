"""kiff-scan -- find where an AI agent can reach a consequential action with no
state-aware decision on the path.

Static analysis only. This package never imports, executes, or evaluates the
code it analyses, and contains no network code of any kind: no telemetry, no
update check, no upload. `tests/test_no_egress.py` enforces that on every
commit, so it is a checked property rather than a promise in a README.

Library use:

    from kiff_scan import scan_path, to_json

    result = scan_path("./my-agent")
    for finding in result.ungoverned:
        print(finding.tool, finding.category, finding.evidence.detail)
"""

from __future__ import annotations

__version__ = "0.2.0"

from .config import Config, load_config
from .engine import scan_file, scan_path, scan_source
from .model import DecisionEvidence, Evidence, Finding, ScanResult, UnsupportedFile
from .report.json_out import to_json, to_markdown
from .report.pretty import render
from .report.sarif import to_sarif
from .taxonomy import CONSEQUENCES, Consequence, meets_threshold

__all__ = [
    "CONSEQUENCES",
    "Config",
    "Consequence",
    "DecisionEvidence",
    "Evidence",
    "Finding",
    "ScanResult",
    "UnsupportedFile",
    "__version__",
    "load_config",
    "meets_threshold",
    "render",
    "scan_file",
    "scan_path",
    "scan_source",
    "to_json",
    "to_markdown",
    "to_sarif",
]

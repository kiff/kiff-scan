"""Release invariants for the published composite GitHub Action."""

from __future__ import annotations

import json
import pathlib

from test_zero_deps import _load_pyproject

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION = REPO_ROOT / "action.yml"


def _input_default(name: str) -> str:
    lines = ACTION.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"  {name}:")
    for line in lines[start + 1 :]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        if line.startswith("    default: "):
            return json.loads(line.removeprefix("    default: "))
    raise AssertionError(f"input {name!r} has no default")


def test_action_package_version_matches_release():
    assert _input_default("version") == _load_pyproject()["project"]["version"]


def test_action_uses_supported_codeql_upload():
    assert "github/codeql-action/upload-sarif@v4" in ACTION.read_text(encoding="utf-8")


def test_action_applies_config_to_reports_and_enforcement():
    action = ACTION.read_text(encoding="utf-8")
    assert action.count('args+=(--config "${{ inputs.config }}")') == 2
    assert '"${args[@]:0:2}"' not in action


def test_action_enforces_threshold_after_reporting():
    action = ACTION.read_text(encoding="utf-8")
    assert action.index("- name: Upload SARIF") < action.index("- name: Enforce threshold")
    assert action.count("--fail-on none") == 4

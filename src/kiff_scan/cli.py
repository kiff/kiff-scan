"""Command line interface.

Exit codes:

    0   no findings at or above the --fail-on threshold
    1   findings at or above the threshold
    2   usage error (bad arguments, missing path, unusable config)

The CLI default for --fail-on is "medium". A scanner whose exit code is its only
machine-readable signal, and which returns 0 while reporting unguarded actions
that can move money, produces exactly the false assurance this tool exists to
remove. The GitHub Action defaults to "none" instead, because it has its own
reporting surface (a PR comment and a SARIF upload) and a team adopting the tool
against an untriaged baseline should not have their build broken on day one.
The two defaults differ on purpose.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import Config, ConfigError, load_config
from .engine import scan_path
from .model import Finding, ScanResult
from .report.json_out import to_json, to_markdown
from .report.pretty import render, render_explain
from .report.sarif import to_sarif
from .taxonomy import SEVERITIES, meets_threshold

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

FORMATS = ("pretty", "json", "sarif", "markdown")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kiff-scan",
        description=(
            "Find where an AI agent can reach a consequential action with no "
            "state-aware decision on the path."
        ),
        epilog=(
            "Exit codes: 0 = clean at threshold, 1 = findings at or above "
            "threshold, 2 = usage error."
        ),
    )
    parser.add_argument("--version", action="version", version=f"kiff-scan {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", nargs="?", default=".", help="file or directory (default: .)")
    scan.add_argument(
        "--format", choices=FORMATS, default="pretty", help="output format (default: pretty)"
    )
    scan.add_argument("--output", metavar="FILE", help="write the report to FILE instead of stdout")
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="medium",
        help="exit 1 at this severity or above (default: medium; 'none' never fails)",
    )
    scan.add_argument("--config", metavar="FILE", help="config file (default: ./.kiff-scan.json)")
    scan.add_argument(
        "--guard",
        action="append",
        default=[],
        metavar="NAME",
        help="treat NAME() as a guard that clears a finding (repeatable)",
    )
    scan.add_argument(
        "--tool-decorator",
        action="append",
        default=[],
        metavar="NAME",
        help="treat @NAME as exposing a function to the model (repeatable)",
    )
    scan.add_argument(
        "--show-unsupported", action="store_true", help="list files that could not be analysed"
    )

    explain = sub.add_parser("explain", help="show the analysed path for one finding")
    explain.add_argument("location", help="FILE:LINE, as printed by scan")
    explain.add_argument("--config", metavar="FILE", help="config file")

    return parser


def _effective_config(args: argparse.Namespace, root: str) -> Config:
    cfg = load_config(root, getattr(args, "config", None))
    cfg.guards.extend(getattr(args, "guard", []) or [])
    cfg.tool_decorators.extend(getattr(args, "tool_decorator", []) or [])
    return cfg


def _emit(text: str, output: str | None) -> None:
    if not output:
        sys.stdout.write(text)
        return
    parent = os.path.dirname(os.path.abspath(output))
    os.makedirs(parent, exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {output}", file=sys.stderr)


def _render(result: ScanResult, fmt: str, root: str) -> str:
    if fmt == "json":
        return to_json(result, root)
    if fmt == "sarif":
        return to_sarif(result, root)
    if fmt == "markdown":
        return to_markdown(result, root)
    header = "kiff-scan · what can this agent do without a decision?\n"
    return header + render(result, root)


def _cmd_scan(args: argparse.Namespace) -> int:
    root = args.path
    if not os.path.exists(root):
        print(f"kiff-scan: path not found: {root}", file=sys.stderr)
        return EXIT_USAGE

    try:
        cfg = _effective_config(args, root)
    except ConfigError as exc:
        print(f"kiff-scan: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = scan_path(root, cfg)
    _emit(_render(result, args.format, root), args.output)

    if args.show_unsupported and result.unsupported:
        print("\n  Not analysed (never counted as clean):", file=sys.stderr)
        for item in result.unsupported:
            print(f"    {item.path}  --  {item.why}", file=sys.stderr)

    failing = [f for f in result.ungoverned if meets_threshold(f.severity, args.fail_on)]
    return EXIT_FINDINGS if failing else EXIT_OK


def _parse_location(location: str) -> tuple[str, int]:
    path, _, line = location.rpartition(":")
    if not path or not line.isdigit():
        raise ValueError("expected FILE:LINE")
    return path, int(line)


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        path, line = _parse_location(args.location)
    except ValueError as exc:
        print(f"kiff-scan: {exc} (got {args.location!r})", file=sys.stderr)
        return EXIT_USAGE

    if not os.path.isfile(path):
        print(f"kiff-scan: file not found: {path}", file=sys.stderr)
        return EXIT_USAGE

    try:
        cfg = _effective_config(args, path)
    except ConfigError as exc:
        print(f"kiff-scan: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = scan_path(path, cfg)
    match: Finding | None = next((f for f in result.findings if f.line == line), None)
    if match is None:
        # Be helpful rather than terse: list what is actually there.
        print(f"kiff-scan: no finding at {path}:{line}", file=sys.stderr)
        if result.findings:
            print("  findings in this file:", file=sys.stderr)
            for f in result.findings:
                print(f"    {f.file}:{f.line}  {f.tool}()", file=sys.stderr)
        return EXIT_USAGE

    sys.stdout.write(render_explain(match, path))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)

    # Allow `kiff-scan .` as shorthand for `kiff-scan scan .`, since scanning is
    # the overwhelmingly common case.
    known = {"scan", "explain"}
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        argv = ["scan"] + argv
    elif not argv:
        argv = ["scan", "."]

    args = parser.parse_args(argv)

    if args.command == "explain":
        return _cmd_explain(args)
    if args.command == "scan":
        return _cmd_scan(args)

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

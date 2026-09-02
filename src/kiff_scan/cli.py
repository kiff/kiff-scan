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
from .assessment import Readiness, assess
from .config import Config, ConfigError, load_config
from .engine import scan_path
from .model import Finding, ScanResult
from .report.assessment import assessment_to_html, assessment_to_json, assessment_to_markdown
from .report.json_out import to_json, to_markdown
from .report.pretty import render, render_explain
from .report.sarif import to_sarif
from .taxonomy import SEVERITIES, meets_threshold

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

FORMATS = ("pretty", "json", "sarif", "markdown")
ASSESSMENT_FORMATS = ("markdown", "json", "html")


def _add_analysis_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--config", metavar="FILE", help="config file (default: ./.kiff-scan.json)"
    )
    command.add_argument(
        "--guard",
        action="append",
        default=[],
        metavar="NAME",
        help="treat NAME() as a guard that clears a finding (repeatable)",
    )
    command.add_argument(
        "--tool-decorator",
        action="append",
        default=[],
        metavar="NAME",
        help="treat @NAME as exposing a function to the model (repeatable)",
    )
    command.add_argument(
        "--include-tests",
        action="store_true",
        help=(
            "count findings in test/example/cookbook code (default: listed but set aside "
            "from the totals and the exit code)"
        ),
    )


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
    _add_analysis_options(scan)
    scan.add_argument(
        "--show-unsupported", action="store_true", help="list files that could not be analysed"
    )

    # `evidence` reports what the source can prove about the agents in a
    # repository. It is deliberately not called an audit: it never executes the
    # target, so it cannot test whether a claimed guarantee actually holds. That
    # is the job of the separate kiff-audit workflow, which consumes this
    # command's JSON as one of its evidence inputs.
    for name in ("evidence", "assess"):
        deprecated = name == "assess"
        parser_kwargs = {}
        if not deprecated:
            # The alias is intentionally omitted from the subcommand list: it
            # still works, but nothing should learn it from the help output.
            parser_kwargs["help"] = "report what the source can prove about agent governability"
        assessment = sub.add_parser(
            name,
            **parser_kwargs,
            description=(
                "Deprecated alias for `kiff-scan evidence`. Use `evidence` instead."
                if deprecated
                else "Report what static analysis can prove about the agents in a "
                "repository, and say plainly what it cannot."
            ),
        )
        assessment.add_argument(
            "path", nargs="?", default=".", help="file or directory (default: .)"
        )
        assessment.add_argument(
            "--format",
            choices=ASSESSMENT_FORMATS,
            default="markdown",
            help="report format (default: markdown)",
        )
        assessment.add_argument(
            "--output", metavar="FILE", help="write the report to FILE instead of stdout"
        )
        _add_analysis_options(assessment)

    explain = sub.add_parser("explain", help="show the analysed path for one finding")
    explain.add_argument("location", help="FILE:LINE, as printed by scan")
    explain.add_argument("--config", metavar="FILE", help="config file")

    return parser


def _effective_config(args: argparse.Namespace, root: str) -> Config:
    cfg = load_config(root, getattr(args, "config", None))
    cfg.guards.extend(getattr(args, "guard", []) or [])
    cfg.tool_decorators.extend(getattr(args, "tool_decorator", []) or [])
    if getattr(args, "include_tests", False):
        cfg.include_tests = True
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


def _cmd_assess(args: argparse.Namespace) -> int:
    root = args.path
    if not os.path.exists(root):
        print(f"kiff-scan: path not found: {root}", file=sys.stderr)
        return EXIT_USAGE

    try:
        cfg = _effective_config(args, root)
    except ConfigError as exc:
        print(f"kiff-scan: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = assess(scan_path(root, cfg), root)
    if args.format == "json":
        rendered = assessment_to_json(report)
    elif args.format == "html":
        rendered = assessment_to_html(report)
    else:
        rendered = assessment_to_markdown(report)
    _emit(rendered, args.output)
    return EXIT_FINDINGS if report.readiness is Readiness.NOT_READY else EXIT_OK


def _parse_location(location: str) -> tuple[str, int]:
    path, _, line = location.rpartition(":")
    if not path or not line.isdigit():
        raise ValueError("expected FILE:LINE")
    return path, int(line)


def _resolve_against_root(path: str, args: argparse.Namespace) -> str | None:
    """Find `path` relative to the scan root or the current tree, or None."""
    candidates = [getattr(args, "path", None) or ".", "."]
    for base in candidates:
        root = base if os.path.isdir(base) else os.path.dirname(os.path.abspath(base))
        candidate = os.path.join(root or ".", path)
        if os.path.isfile(candidate):
            return candidate
    # Last resort: a unique basename match under the current tree.
    target = os.path.basename(path)
    matches: list[str] = []
    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if target in filenames:
            matches.append(os.path.join(dirpath, target))
            if len(matches) > 1:
                return None
    return matches[0] if len(matches) == 1 else None


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        path, line = _parse_location(args.location)
    except ValueError as exc:
        print(f"kiff-scan: {exc} (got {args.location!r})", file=sys.stderr)
        return EXIT_USAGE

    if not os.path.isfile(path):
        # A path printed by a previous scan may be relative to the scan root
        # rather than to where the user is standing. Retry against the
        # configured root before giving up, so the report's own `Next:` line
        # works wherever it is pasted.
        resolved = _resolve_against_root(path, args)
        if resolved is None:
            print(f"kiff-scan: file not found: {path}", file=sys.stderr)
            return EXIT_USAGE
        path = resolved

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
    known = {"scan", "evidence", "assess", "explain"}
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        argv = ["scan"] + argv
    elif not argv:
        argv = ["scan", "."]

    args = parser.parse_args(argv)

    if args.command == "explain":
        return _cmd_explain(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command in ("evidence", "assess"):
        if args.command == "assess":
            print(
                "kiff-scan: `assess` is deprecated and will be removed in a future "
                "release; use `kiff-scan evidence` instead.",
                file=sys.stderr,
            )
        return _cmd_assess(args)

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

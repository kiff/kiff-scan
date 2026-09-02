"""Measure kiff-scan against pinned public agent repositories.

The question this answers is the one a reader asks first: *how accurate is
this on code that isn't your own fixtures?* Fixture-only test suites cannot
answer it, and a scanner that has never been pointed at real code is a
prototype regardless of how many tests it has.

Labels live in bench/expected/<name>.json and were produced by reading the
source at the pinned commit. Every label carries a `why` so a disagreement is
a conversation about the code rather than about the number.

    python bench/run.py                 # clone (cached), scan, print the table
    python bench/run.py --repo strands-tools
    python bench/run.py --json          # machine-readable, for CI

Requires network on first run only; clones are cached under bench/.cache.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CACHE = os.path.join(HERE, ".cache")

sys.path.insert(0, os.path.join(ROOT, "src"))

from kiff_scan.engine import scan_path  # noqa: E402


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def ensure_clone(repo: dict) -> str | None:
    """Shallow-clone at the pinned commit. Returns the path to scan."""
    dest = os.path.join(CACHE, repo.get("clone") or repo["name"])
    if not os.path.isdir(os.path.join(dest, ".git")):
        os.makedirs(dest, exist_ok=True)
        cmds = [
            ["git", "init", "-q"],
            ["git", "remote", "add", "origin", repo["url"]],
            ["git", "fetch", "-q", "--depth", "1", "origin", repo["commit"]],
            ["git", "checkout", "-q", "FETCH_HEAD"],
        ]
        for cmd in cmds:
            done = subprocess.run(cmd, cwd=dest, capture_output=True, text=True)
            if done.returncode != 0:
                print(f"  ! clone failed for {repo['name']}: {done.stderr.strip()[:200]}")
                return None

    target = os.path.join(dest, repo.get("subdir", "")) if repo.get("subdir") else dest
    return target if os.path.isdir(target) else None


def key(finding) -> str:
    return f"{os.path.basename(finding.file)}::{finding.tool}"


#: The bench scores what a user is asked to review: findings at the CLI's
#: default threshold (medium) or above, in product code. Low-severity findings
#: -- a fixed program with model-controlled arguments -- are counted but not
#: scored, and findings set aside as test/example code are not scored either.
SCORED_SEVERITIES = ("medium", "high")


def evaluate(repo: dict, path: str) -> dict:
    expected_path = os.path.join(HERE, "expected", f"{repo['name']}.json")
    labels = _load(expected_path) if os.path.isfile(expected_path) else {"true": [], "false": []}

    started = time.time()
    result = scan_path(path)
    elapsed = time.time() - started

    reported = {key(f) for f in result.ungoverned if f.severity in SCORED_SEVERITIES}
    low = {key(f) for f in result.ungoverned if f.severity not in SCORED_SEVERITIES}
    should_find = {item["id"] for item in labels.get("true", [])}
    should_not = {item["id"] for item in labels.get("false", [])}

    tp = sorted(reported & should_find)
    fn = sorted(should_find - reported)
    # Anything reported that we labelled as "must not report" is a false
    # positive. Findings we have not labelled either way are counted as
    # unlabelled rather than silently scored, so the numbers never flatter
    # themselves by treating unknowns as correct.
    fp = sorted(reported & should_not)
    unlabelled = sorted(reported - should_find - should_not)

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else None
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else None

    return {
        "repo": repo["name"],
        "files": result.files,
        "reported": len(reported),
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "unlabelled": len(unlabelled),
        "low": len(low),
        "test_code": len(result.test_code),
        "precision": precision,
        "recall": recall,
        "seconds": round(elapsed, 2),
        "detail": {"tp": tp, "fp": fp, "fn": fn, "unlabelled": unlabelled, "low": sorted(low)},
    }


def _fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="run a single repo by name")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--verbose", action="store_true", help="list every labelled miss")
    args = parser.parse_args()

    repos = _load(os.path.join(HERE, "repos.json"))["repos"]
    if args.repo:
        repos = [r for r in repos if r["name"] == args.repo]
        if not repos:
            print(f"no such repo: {args.repo}", file=sys.stderr)
            return 2

    rows: list[dict] = []
    for repo in repos:
        if not args.json:
            print(f"  {repo['name']} ... ", end="", flush=True)
        path = ensure_clone(repo)
        if path is None:
            if not args.json:
                print("skipped (clone unavailable)")
            continue
        row = evaluate(repo, path)
        rows.append(row)
        if not args.json:
            print(f"{row['reported']} reported in {row['seconds']}s")

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    if not rows:
        print("\nNo repositories could be scanned. Network required on first run.")
        return 1

    print()
    header = (
        f"{'repo':<24} {'files':>6} {'rep':>5} {'TP':>4} {'FP':>4} {'FN':>4} {'unlab':>6} "
        f"{'low':>4} {'test':>5} {'prec':>6} {'rec':>6} {'time':>7}"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['repo']:<24} {r['files']:>6} {r['reported']:>5} {r['tp']:>4} {r['fp']:>4} "
            f"{r['fn']:>4} {r['unlabelled']:>6} {r['low']:>4} {r['test_code']:>5} "
            f"{_fmt(r['precision']):>6} {_fmt(r['recall']):>6} {r['seconds']:>6}s"
        )

    tp = sum(r["tp"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows)
    unlab = sum(r["unlabelled"] for r in rows)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    print("-" * len(header))
    print(
        f"{'TOTAL':<24} {sum(r['files'] for r in rows):>6} {sum(r['reported'] for r in rows):>5} "
        f"{tp:>4} {fp:>4} {fn:>4} {unlab:>6} {sum(r['low'] for r in rows):>4} "
        f"{sum(r['test_code'] for r in rows):>5} {_fmt(precision):>6} {_fmt(recall):>6} "
        f"{sum(r['seconds'] for r in rows):>6.2f}s"
    )
    print()
    print(f"  {unlab} reported finding(s) are unlabelled and scored as neither.")
    print(
        "  Scored: medium/high findings in product code. `low` and `test` are counted, not scored."
    )
    if fn:
        print(f"  {fn} labelled finding(s) are NOT reached. Recall below 1.00 is deliberate;")
        print("  each is a known miss described in bench/repos.json.")
    print("  Labels: bench/expected/*.json. Disagreements are issues, not defects in the number.")

    if args.verbose:
        for r in rows:
            for kind in ("fp", "fn", "unlabelled"):
                for item in r["detail"][kind]:
                    print(f"    {r['repo']:<22} {kind.upper():<10} {item}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

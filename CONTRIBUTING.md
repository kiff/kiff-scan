# Contributing

## Setup

```bash
git clone https://github.com/kiff/kiff-scan
cd kiff-scan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

There is no build step and no compilation. `pytest` should run in under a second.

## The two rules that are not negotiable

**1. No runtime dependencies.** `pyproject.toml`'s `dependencies` list stays
empty. This is the property that lets a security team run kiff-scan against a
codebase that has adopted nothing, and it is enforced by
`tests/test_zero_deps.py`. If you believe a dependency is genuinely required,
open an issue first — it is a product decision, not a refactor.

**2. No network code.** No `socket`, `urllib`, `http`, `requests`, or anything
that can open a connection, anywhere in the package. Also no `subprocess` and no
`ctypes`. Enforced by `tests/test_no_egress.py`, which checks the import graph,
runs a scan with the socket constructor sabotaged, and verifies a scan writes
nothing.

Both are checked on every push. A pull request that trips either gate will fail
before review.

## Adding a sink

Sinks live in `src/kiff_scan/detectors/sinks.py`.

1. Add the call's final attribute to `SINK_CALLS`, mapped to a consequence
   category. Match the method name, not the full qualified path, so that
   `client.delete_thing()` and `boto3.client("x").delete_thing()` both resolve.
2. Add a case to `tests/fixtures/` and assert it in `tests/test_engine.py`.
3. If it needs a new category, add it to `src/kiff_scan/taxonomy.py` and decide
   `state_dependent` deliberately — see below.

## Adding a guard

Guards live in `src/kiff_scan/detectors/decisions.py`. Vendor neutrality is a
design commitment: a codebase's own `authorize()` must clear a finding exactly as
a KIFF decision does. Do not add a check that privileges KIFF over an equivalent
in-house guard.

## Deciding `state_dependent`

Ask: *can this action be fully authorized, requested by a legitimate principal,
with valid inputs, and still be the wrong thing to do because of the state of the
world right now?*

If yes, it is state-dependent (a rollback to a bad revision, a failover to the
active region, a second refund on an unsettled order). If an authorization check
plus input validation genuinely closes it, it is not (arbitrary shell execution).

Getting this wrong in either direction misleads the reader, so justify it in the
`why` field, which is printed in the report.

## Reporting a scanner mistake

A case where the scanner is wrong is the most valuable contribution. In scope:

- a supported-language sink it misses
- a recognised guard it fails to honour
- a finding on code with no model-controlled input on the path
- any case where it reports clean when it should not

Open an issue with a minimal reproducing file. Accepted cases become permanent
fixtures, credited by GitHub handle. Known misses stay listed even before they
are fixed; a challenge list that only shows fixed cases is a trophy cabinet.

## Style

`ruff check src tests` and `ruff format --check src tests` must pass. Comments
should explain *why*, especially where a detector is deliberately conservative —
that reasoning is the part a future reader cannot reconstruct.

## Tests

New behaviour needs a test. Fixtures under `tests/fixtures/` are scanner *input*
and must never be imported or collected; `pyproject.toml` ignores that directory
for collection, and the repository's own `.kiff-scan.json` excludes it from a
self-scan.

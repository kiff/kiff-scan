# Threat model

You are considering pointing this tool at proprietary source code. This document
states what it does, what it cannot do, and how each claim is enforced rather
than asserted.

## The short version

kiff-scan reads source files you name, parses them in-process, and writes a
report to stdout or a file you specify. It has no network code, no telemetry, no
dependencies, and it never executes the code it analyses.

It is not "encrypted in transit" because nothing is transmitted. That is a
stronger property than encryption: there is no channel, no key, and no vendor to
trust with your source.

## Properties, and how each is enforced

| Property | Enforcement |
|---|---|
| No network connection of any kind | `tests/test_no_egress.py` rejects any import of `socket`, `ssl`, `http`, `urllib`, `requests`, `httpx`, `aiohttp` and similar, in every module of the package |
| No telemetry or analytics | Same gate, plus a check for analytics SDK names |
| Opens no socket during a real scan | The socket constructor is replaced with one that fails the test, then a full scan is run |
| Passes with networking disabled | A CI job drops all outbound traffic with `iptables` and runs the suite |
| Never executes analysed code | A test writes a hostile file that would create a sentinel on import; the sentinel must not exist after the scan |
| Read-only on disk | A test intercepts `open()` and fails on any write mode during a scan, and compares mtimes before and after |
| Zero runtime dependencies | `tests/test_zero_deps.py` reads `pyproject.toml`; a CI job installs the built wheel into a clean venv and fails if anything else appears |
| No third-party code needed to import | A test reloads the package with `site-packages` removed from `sys.path` |

Every one of these runs on each push, each pull request, and on a daily
schedule. A claim in this document that stops being true turns the build red.

## Data handling

**What is read:** files with a supported extension under the path you pass, minus
excluded directories. Nothing else is opened.

**What is written:** nothing, unless you pass `--output FILE`.

**What a report contains:** file paths, line numbers, function names, consequence
categories, and **parameter names** taken from function signatures. A test
asserts that argument *values* and source text never appear in a finding, so a
report cannot become a place where literals or credentials are copied out of your
code.

**Retained state:** none. There is no cache, no config written back, no
telemetry buffer, no lock file.

## Why zero dependencies is a security property

A dependency tree is the most common way a developer tool acquires the ability
to phone home, and you cannot audit one package — you audit all of them,
transitively, forever. Zero dependencies means installing kiff-scan adds exactly
one auditable unit to your environment, and the whole package is small enough to
read in a sitting. That auditability is the point; keeping the codebase small is
therefore a security decision, not a style preference.

## Handling the report

The report deserves more care than the scan. A findings list is a precise map of
the unguarded ways to move money, delete data, or change access in your system —
useful to you, and useful to an attacker.

- Treat the output as sensitive. Prefer private channels.
- In CI, SARIF goes to your own repository's Security tab and the pull request
  comment is posted with your own `GITHUB_TOKEN`. Nothing is sent anywhere else.
- Findings reference paths and line numbers, so a report reveals structure. If
  you must share one externally, review it first.

## Verifying the artifact you installed

The properties above are properties of *this source*. To know that the package
you installed corresponds to it:

- Install from a pinned version, and prefer a hash-pinned lock file.
- Check the release provenance attestation published with each release.
- Or clone and run from source; there is no build step and nothing to compile.

## Residual risk, stated plainly

- You must trust that the distributed artifact matches the published source.
  Signing and provenance reduce this; they do not eliminate it.
- A scan report is sensitive by its nature, and its handling is yours.
- A clean scan means no supported path was identified. It does not mean the
  codebase is safe. See [COVERAGE.md](./COVERAGE.md) for what is not analysed.
- Findings are not vulnerabilities. They are places where a consequential action
  is reachable with no decision found on the analysed path, which is a
  starting point for review, not a verdict.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).

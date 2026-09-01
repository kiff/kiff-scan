# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-01

### Fixed

- Pin the package installed by each GitHub Action tag to the matching release,
  so an existing Action tag cannot silently change when PyPI receives a newer
  version.
- Apply the Action's `config` input to SARIF, JSON, Markdown, terminal output,
  and threshold enforcement.
- Generate and publish reports before enforcing `fail-on`, including when a
  finding exceeds the configured threshold.
- Upgrade SARIF upload to `github/codeql-action/upload-sarif@v4`.

## [0.1.0] — 2026-09-01

First release.

### Added

- Static analysis of Python source for agent-reachable consequential actions.
  A finding requires all three of: reachable by a model, consequential, and no
  decision found on the analysed path.
- Eight consequence categories, seven of them marked `state_dependent` — the
  cases where an authorization check is necessary but not sufficient because the
  action's safety depends on live state at the moment of execution.
- Per-function decision detection with named evidence levels (`decorator`,
  `call_before_sink`, `module_hook`, `call_after_sink`, `none`), including
  lexical precedence so a guard that runs *after* the consequential call is
  reported rather than credited.
- Vendor-neutral guard vocabulary: roughly 30 common authorization and approval
  function names recognised out of the box, extensible with `--guard` or config.
- Match confidence (`call` vs `declared`), with name-only inferences capped below
  `high` severity so they cannot fail a build on their own.
- Bounded interprocedural analysis: calls to functions defined in the same module
  are followed up to four hops, so a tool that delegates its destructive work to
  a helper is still reported, with the chain named in the reason. Cycles
  terminate, and guards inside the chain are credited so the added reach does not
  create false positives.
- Reporters: terminal, JSON (`schema_version: 1`), SARIF 2.1.0, and Markdown.
- `explain FILE:LINE` for the analysed path behind one finding.
- `--fail-on {none,low,medium,high}`, defaulting to `medium` in the CLI and
  `none` in the GitHub Action.
- Unsupported files are reported explicitly and never counted as clean.
- Configuration via `.kiff-scan.json`: custom guards, custom tool decorators,
  exclude globs, and excluded directories.
- GitHub Action with a sticky pull request comment and SARIF upload.
- Security gates in CI: no network-capable imports, no telemetry, no socket
  opened during a scan, the suite passing with outbound traffic blocked, no
  execution of analysed code, read-only on disk, and zero runtime dependencies
  verified against a clean install of the built wheel.

### Notes

Python only in this release. TypeScript and Go files are reported as unsupported
rather than skipped silently. See [docs/COVERAGE.md](./docs/COVERAGE.md) for the
full list of what is and is not analysed, and the known limitations of decision
detection.

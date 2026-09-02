# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-02

The pre-launch release. A full read of the scanner against thirteen public
agent codebases found that its two loudest behaviours were both wrong: it
reported innocent code as dangerous, and reported the canonical dangerous
tools as clean. Everything here follows from that.

### Fixed — precision

- Execution detection is receiver-aware. `agent.run()`, `chain.run()` and
  `client.call()` are delegation, not shell execution; a call now needs an
  execution receiver (`subprocess`, `os`, `asyncio`, `pexpect`, `pty`) or an
  explicit `shell=True`. On pydantic-ai's examples this alone removed every
  finding, all of which were `agent.run()`.
- `capture`, `refund`, `upgrade`, `downgrade` and `update_service` require
  corroboration from the receiver or a parameter name. `rich`'s
  `Console().capture()` is no longer money movement.
- Identifiers are matched on whole semantic tokens rather than substrings, so
  "drop" is a token of `drop_database` and is not a token of `select_dropdown`.
- The function name outranks the docstring, only the docstring's first
  sentence is consulted, a read-only name prefix (`get_`, `list_`, `check_`…)
  vetoes a declared finding, and names containing `help`/`docs`/`guide` are
  treated as informational.

### Fixed — recall

- `exec()` and `eval()` as builtins, the `os.exec*` family,
  `asyncio.create_subprocess_*`, `pexpect.spawn` and `posix_spawn` are sinks.
  A Python REPL and a PTY shell no longer scan clean.
- Class-based tools are reachable: a `_run`/`_arun`/`run`/`execute`/`__call__`
  method on a class deriving from a `Tool`/`BaseTool`/`Toolkit` base.
- Registration without a decorator is recognised:
  `StructuredTool.from_function(fn)`, `Tool(func=fn)`, `X.tool(...)(fn)`, and
  module-level `TOOL_SPEC` declarations.
- `@agent.tool_plain`, `@server.call_tool()` and `@kernel_function` are tool
  decorators.
- Generic `@task`/`@action`/`@component`/`@skill` only count when the module
  imports an agent framework, so a Celery repo with no LLM in it stops
  reporting an agent blast radius.

### Fixed — evidence

- A declared-confidence finding anchored its sink on the `def` line, so every
  guard in the function body was reported as arriving "after the sink". That
  was a false and checkable accusation about the claim this tool leads with.
- Same-line ordering compares column offsets, so
  `if authorize(x): delete(x)` is credited.
- Framework-native human-in-the-loop metadata is decision evidence:
  `requires_confirmation=True`, `needs_approval=True`,
  `requires_user_input=True`, `external_execution=True`.
- MCP `ToolAnnotations` are read. `readOnlyHint=True` on a genuine read
  suppresses the finding; on a tool that reaches a destructive call it is
  reported as an **annotation mismatch** in its own section.
  `destructiveHint=True` surfaces the tool at `annotated` confidence.

### Fixed — CLI and report

- The `Next:` line the report prints now runs when copied. It was relative to
  the scan root and failed from anywhere else.
- A scan with no findings no longer claims it "established that a
  model-controlled parameter reaches a consequential call".

### Added

- `bench/`: six public agent repositories pinned at exact commits, with
  hand-labelled expected findings and a runner reporting precision and recall.
  `python bench/run.py`.

### Performance

- Files are parsed once instead of twice, and modules with no
  tool-registration token skip the detector passes. browser-use 9.1s → 6.7s.

### Known limitations

- Calls are followed within a module only. On multi-module MCP servers this is
  the largest remaining source of false negatives.
- `Agent(tools=[fn])` list registration and JSON-schema dispatch tables are not
  yet resolved. See `docs/COVERAGE.md`.

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

# Coverage

What kiff-scan looks at, what it deliberately does not, and where it is known to
be wrong. Read this before trusting a clean result.

## Languages

| Language | Status |
|---|---|
| Python | Supported (`ast`, standard library) |
| TypeScript / JavaScript | Not supported — reported as unsupported |
| Go | Not supported — reported as unsupported |
| Everything else | Not supported — reported as unsupported |

An unsupported file is **never** counted as clean. It is listed in the report
and in the JSON output. A repository whose agent is written in TypeScript will
scan as 0 findings with a visible warning, not as a pass.

## What a finding requires

All three must hold:

1. **Reachable** — the function is exposed to a model, via a recognised tool
   decorator or a declared action mapping.
2. **Consequential** — the function reaches a recognised sink, or its name and
   docstring declare a recognised consequential action.
3. **Undecided** — no recognised guard, authorization check, or decision was
   found on the analysed path.

Miss any one and there is no finding. A destructive call in a private helper is
not reported, because a model cannot invoke it.

## Reachability

Recognised tool decorators, matched on the final attribute so `@mcp.tool()`,
`@agent.tool` and a bare `@tool` all resolve:

`tool`, `tools`, `function_tool`, `agent_tool`, `ai_function`, `openai_function`,
`register_tool`, `task`, `component`, `skill`, `action`

Recognised declared mappings — a dict assigned to one of `TOOL_ACTION`,
`TOOL_ACTIONS`, `ACTION_MAP`, `ACTIONS`, `TOOL_ACTION_MAP`, `GOVERNED_ACTIONS`,
`KIFF_ACTIONS`, or a `registry.bind("tool", action="ACTION")` call.

Add your framework's decorator with `--tool-decorator NAME` or the
`tool_decorators` config key. No fork required.

**Not detected:** tools registered by passing bare function references to an
agent constructor without a decorator, dynamic registration through a loop or a
metaclass, and tools defined in a language other than Python.

## Consequence categories

| Category | State-dependent | Meaning |
|---|---|---|
| `DATA_LOSS` | yes | Dropping or deleting stored data |
| `COMPUTE` | yes | Terminating compute capacity |
| `DEPLOYMENT` | yes | Deploys, rollbacks, restarts, scaling |
| `NETWORK` | yes | Traffic shifts, failover, DNS |
| `IDENTITY` | yes | Secrets, credentials, access grants |
| `DATABASE` | yes | Schema changes and migrations |
| `MONEY` | yes | Payments, refunds, payouts |
| `EXECUTION` | no | Shell and arbitrary command execution |

`state_dependent` marks the categories where an authorization check is necessary
but not sufficient, because the action's safety depends on live state at the
moment of execution rather than on the identity of the caller.

## Match confidence

| Confidence | Meaning | Effect |
|---|---|---|
| `call` | A recognised SDK call was found, in the function body or in a module-local helper it calls | Full severity |
| `declared` | Classified from the function name and docstring only | Capped at `medium` |

Two further modifiers apply to `call` findings:

| Modifier | Meaning | Effect |
|---|---|---|
| fixed program | The execution sink runs a constant, non-interpreter `argv[0]` (`say`, `git`, `ffmpeg`) with model-controlled arguments and no `shell=True` | `low` — the model chooses the arguments, not the program. Interpreters (`sh`, `python3`, `osascript`, `crontab`, `docker`…) stay `high` |
| test code | The file is under `tests/`, `test/`, `examples/`, `cookbook/`, `docs/`, `fixtures/`, or is `test_*.py`/`*_test.py`/`conftest.py`, relative to the scan root | Listed but set aside: excluded from totals, "Most exposed" and the exit code unless `--include-tests` |

The weaker signal is kept because agent tool bodies are frequently thin wrappers
that delegate to a service, and dropping them would report clean on an agent
that can plainly drop a database. It is capped rather than trusted, so a
name-based inference alone cannot fail a build at `--fail-on high`.

## Following calls

Agent tools are commonly thin wrappers, so stopping at the tool body reports
clean on an agent that can plainly delete a database:

```python
def _perform(target):
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=target)

@tool
def handle_request(target: str):     # neither the name nor the docstring hints
    "Process an operations request." # at anything destructive
    return _perform(target)
```

kiff-scan follows calls to **functions defined in the same module**, up to four
hops, and reports the chain: `calls _perform() which calls delete_db_instance()`.
Cycles terminate. Guards found inside the chain are credited, so moving an
`authorize()` into the helper does not turn a guarded tool into a finding.

**Not followed:** calls into other modules or installed packages, methods
resolved through an instance attribute whose class is defined elsewhere, and
anything dispatched dynamically (a dict of callables, `getattr`, a registry).
A destructive call one import away is still missed.


## Decision detection

A sink is cleared when one of the following is found, in this precedence order:

| Evidence | Precision |
|---|---|
| `decorator` — a recognised guard decorator wraps the function | High |
| `call_before_sink` — a guard call precedes the sink in the same body | High |
| `module_hook` — a module-level hook installs a guard over every tool | Coarse |
| `call_after_sink` — a guard call exists but runs after the sink | **Reported as a finding** |
| `none` | **Reported as a finding** |

Guard detection is vendor-neutral. A codebase's own `authorize()` clears a
finding exactly as a KIFF decision does. Roughly 30 common authorization and
approval function names are recognised out of the box; add your own with
`--guard NAME` or the `guards` config key.

### Known limitations of decision detection

These are real and worth stating plainly:

- **Lexical precedence, not control flow.** A guard call that appears before the
  sink in source order is credited even if a branch could skip it. This is a
  confirmed false negative: in
  `if not force: authorize(...)` followed by the destructive call, the action is
  reported as governed even though `force=True` skips the check.
- **A guard is credited by name, not by behaviour.** A function called
  `authorize()` that always returns `True` clears the finding. Static analysis
  cannot tell an enforcing check from a stub.
- **Module scope.** A guard applied in a caller, in middleware, in a framework
  hook the scanner does not recognise, or in another file is not seen. This
  produces false positives, which is the safer direction to fail.
- **`module_hook` is coarse by nature.** It credits every tool in the module.
  The report labels it so, and you should confirm the hook is mounted in
  enforcing mode rather than an observe-only mode.
- **No taint tracking.** Every parameter of a reachable tool is treated as
  model-controlled. A tool whose destructive argument is a hard-coded constant
  is still reported.

## Not covered

- Runtime behaviour, network configuration, and deployment topology.
- Whether an attacker can externally reach the agent.
- Whether the operation is reversible in practice.
- Prompt injection, jailbreaks, and model behaviour generally. This tool reads
  code, not prompts.
- Non-Python source.

## Reporting a miss

A case where the scanner is wrong is more useful than a case where it is right.
In scope: a supported-language sink it misses, a recognised guard it fails to
honour, a finding on code with no model-controlled input on the path, or any
case where it reports clean when it should not. Open an issue with a minimal
reproducing file; accepted cases become permanent test fixtures.


## Registration shapes (added after the pre-launch audit)

Measured against the pinned repositories in `bench/`.

| Shape | Example | Recognised |
|---|---|---|
| Decorator | `@mcp.tool()`, `@agent.tool`, `@function_tool` | yes |
| pydantic-ai plain | `@agent.tool_plain` | yes |
| Low-level MCP | `@server.call_tool()` | yes |
| Semantic Kernel | `@kernel_function` | yes |
| Class-based | `class X(BaseTool): def _run(...)` | yes (`_run`, `_arun`, `run`, `execute`, `__call__`); reported as `X._run` |
| Executor | `class X(ToolExecutor[A, O]): def __call__(...)` (OpenHands) | yes — but the sink is usually in another module, see below |
| Function registration | `StructuredTool.from_function(fn)`, `Tool(func=fn)` | yes |
| Curried registration | `self.mcp.tool(name=...)(self.method)` | yes |
| Module spec | `TOOL_SPEC = {"name": "shell"}` + `def shell(...)` | yes (Strands) |
| Generic worker | `@app.task`, `@action`, `@component` | only when the module imports an agent framework |
| List registration | `Agent(tools=[a, b])` | **no** — a plain function passed in a list is not yet resolved |
| Schema dispatch | a JSON tool schema plus a dispatch table | **no** |

The bench's six known misses (`bench/run.py`, recall 0.65) are all the same
gap: the registration shape is recognised, the destructive call is one import
away. Cross-module following within the scanned package is the next item.

## Decision evidence recognised

| Source | Example |
|---|---|
| Guard call before the sink | `authorize(...)` then `delete_db_instance(...)` |
| Guard decorator | `@requires_approval` |
| Guard inside the called helper | the check lives one hop away |
| Module-level hook | `Agent(tool_hooks=[Guard(...)])` |
| Framework confirmation | `requires_confirmation=True`, `needs_approval=True`, `requires_user_input=True`, `external_execution=True` |
| MCP annotation | `ToolAnnotations(readOnlyHint=True)` on a tool with no contradicting call |

`readOnlyHint=True` on a tool that *does* reach a destructive call is not
evidence — it is reported as an annotation mismatch.

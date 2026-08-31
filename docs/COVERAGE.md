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
| `call` | A recognised SDK call was found in the function body | Full severity |
| `declared` | Classified from the function name and docstring only | Capped at `medium` |

The weaker signal is kept because agent tool bodies are frequently thin wrappers
that delegate to a service, and dropping them would report clean on an agent
that can plainly drop a database. It is capped rather than trusted, so a
name-based inference alone cannot fail a build at `--fail-on high`.

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
  sink in source order is credited even if a branch could skip it. A v1
  analyser cannot distinguish `if debug: authorize(...)` from an unconditional
  check.
- **Function scope only.** A guard applied in a caller, a middleware layer, a
  framework hook the scanner does not recognise, or a different file is not
  seen. This produces false positives, which are the safer direction to fail.
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

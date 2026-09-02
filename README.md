# kiff-scan

[![ci](https://github.com/kiff/kiff-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/kiff/kiff-scan/actions/workflows/ci.yml)
[![claims: machine-verified](https://github.com/kiff/kiff-scan/actions/workflows/verify-claims.yml/badge.svg)](https://github.com/kiff/kiff-scan/actions/workflows/verify-claims.yml)
[![PyPI](https://img.shields.io/pypi/v/kiff-scan)](https://pypi.org/project/kiff-scan/)
[![Python](https://img.shields.io/pypi/pyversions/kiff-scan)](https://pypi.org/project/kiff-scan/)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](./pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

> **What can your AI agent do without asking?**

kiff-scan finds the places where a model-controlled parameter reaches an action
that **deletes, deploys, moves money, rotates a credential, or shifts traffic** —
and reports whether anything on that path can refuse it.

It parses **Python**. Other languages are reported as unsupported, never silently
treated as clean.

Zero dependencies. No network code. It never executes the code it reads.

```bash
uvx kiff-scan scan .
```

No install, no account, no config.

---

## The output

Run against [awslabs/mcp](https://github.com/awslabs/mcp)'s IAM server at
`e9f2439` — a real MCP server with real boto3 calls, not a fixture:

```
kiff-scan · what can this agent do without a decision?

  YOUR AGENT'S BLAST RADIUS

  Consequential capabilities: 6
    Decision found on path:   0
    Review required:          6

    Secrets / identity    6   add_user_to_group, attach_user_policy, create_access_key,
                              delete_access_key, delete_user, put_user_policy

  Most exposed: awslabs/iam_mcp_server/server.py:431  delete_user()
    Reachable by:            @tool
    Consequence:             Secrets / identity  (calls delete_access_key())
    Severity:                high
    Match confidence:        call
    Decision on path:        none found on the analysed path
    Model-controlled inputs: user_name, force, confirmed

    State-dependent: an authorization check is necessary but NOT
    sufficient here.
```

Six tools, six IAM mutations, no decision between the model's argument and the
SDK call. Every one is a real `@mcp.tool` in that repository.

And on a fixture built to exercise the report (`tests/fixtures/ungoverned_ops.py`):

```
kiff-scan · what can this agent do without a decision?

  YOUR AGENT'S BLAST RADIUS

  Consequential capabilities: 7
    Decision found on path:   0
    Review required:          7

  Your agent can reach 7 consequential actions with no
  recognised decision on the path.

    Data loss             1   drop_database
    Compute teardown      1   terminate_workers
    Traffic / failover    1   failover_region
    Deploy / rollback     1   rollback_release
    Secrets / identity    1   rotate_db_credentials
    Money movement        1   issue_refund
    Shell / execution     1   run_maintenance

  Most exposed: ungoverned_ops.py:22  drop_database()
    Reachable by:            @tool
    Consequence:             Data loss  (calls delete_db_instance())
    Severity:                high
    Match confidence:        call
    Decision on path:        none found on the analysed path
    Model-controlled inputs: database_id, skip_final_snapshot

    State-dependent: an authorization check is necessary but NOT
    sufficient here.
    Dropping or deleting stored data is irreversible, and whether a given
    target is safe to drop depends on whether it is live.

  7 findings in 1 file  (review required: 5 high, 2 medium, 0 low)

  What this scan did not establish:
    This scan established that a model-controlled parameter reaches a
    consequential call with no recognised decision on the analysed path.
    It did NOT establish that the action is externally reachable, that no
    guard exists elsewhere, that exploitation is practical, or that any
    finding is a vulnerability. A clean scan means no supported path was
    identified -- not that the code is safe.

  Next:
    kiff-scan explain ungoverned_ops.py:22
```

## The idea: an authorization check is not always enough

Most tools in this space ask one question — *is there an auth check on this
path?* That question is necessary, and treating it as sufficient is how a
system that looks governed still destroys something.

Consider four actions that pass every authorization check you can write:

- a **rollback** to a revision that is itself broken
- a **failover** to the region you already failed over to
- a **`DROP`** against the live database rather than the drained replica
- a **refund** issued twice because the first has not settled

Each is legitimate in one state and catastrophic in another. No role check,
signed plan, or API key can tell them apart, because the difference is not *who*
is asking or *what* they are asking for — it is *when*. Only a decision evaluated
against live state can refuse them.

kiff-scan marks these categories `state_dependent` and says so in the report,
because "add an authorization check" is the wrong remediation for them and
following it produces false confidence.

`EXECUTION` — arbitrary shell reachable from model input — is marked *not*
state-dependent, because there an auth check plus strict input handling really
does close it. The distinction is the point.

## Evidence, not verdicts

Every judgement is reported with the evidence that produced it, so you can
disagree with the scanner. This matters most where a file mixes governed and
ungoverned code:

```
  Most exposed: mixed_governance.py:37  drop_production()
    Decision on path:        none found on the analysed path

  1 action has a guard call that runs *after* the
  consequential call, so it cannot have gated it:
    ! delete_backups       authorize() appears at line 50, after the sink

  2 actions cleared, with evidence:
    ok drop_replica         DATA_LOSS          decide() before the sink
    ok scale_cluster        DEPLOYMENT         @requires_approval wraps the function
```

`drop_production` and `drop_replica` live in the same file, one line apart in
structure, and get opposite verdicts. Governance is judged **per function**, with
lexical precedence, and a guard that runs after the destructive call is reported
rather than credited.

Evidence levels: `decorator`, `call_before_sink`, `module_hook` (coarse — labelled
as such), `call_after_sink` (reported), `none` (reported).

## Thin wrappers do not hide the action

Agent tools usually delegate. A scanner that stops at the tool body reports clean
on this, and the function's own name gives nothing away:

```python
def _perform(target):
    boto3.client("rds").delete_db_instance(DBInstanceIdentifier=target)

@tool
def handle_request(target: str):
    "Process an operations request."
    return _perform(target)
```

```
  Most exposed: fn6_neutral.py:7  handle_request()
    Consequence:             Data loss  (calls _perform() which calls delete_db_instance())
    Match confidence:        call
```

Calls to functions in the same module are followed up to four hops, the chain is
printed, and cycles terminate. A guard found inside the chain is credited, so
moving your `authorize()` into the helper does not create a false finding.
Cross-module calls are not followed — see the limitations below.

## Guard detection is vendor-neutral

Your own `authorize()` clears a finding exactly as anything else does. About 30
common authorization and approval names are recognised out of the box —
`authorize`, `check_permission`, `require_role`, `has_permission`, `opa_eval`,
`casbin_enforce`, `cedar_authorize`, `validate_jwt`, and so on. Add yours:

```bash
kiff-scan scan . --guard acme_authorize --tool-decorator my_framework_action
```

or in `.kiff-scan.json`:

```json
{
  "guards": ["acme_authorize", "company_can"],
  "tool_decorators": ["my_framework_action"],
  "exclude": ["tests/fixtures/**"]
}
```

## Your code does not leave your machine

There is nothing to encrypt, because nothing is transmitted.

| Property | How it is enforced |
|---|---|
| No network code anywhere | A test rejects any import of `socket`, `ssl`, `http`, `urllib`, `requests`, `httpx`, `aiohttp`, … in every module |
| No telemetry | Same gate, plus a check for analytics SDK names |
| No socket opened during a scan | The socket constructor is replaced with one that fails the test, then a real scan runs |
| Works with networking off | A CI job drops all outbound traffic and runs the suite |
| Never executes your code | A test plants a file that would create a sentinel on import; the sentinel must not exist after scanning |
| Read-only | A test intercepts `open()` and fails on any write during a scan |
| Zero runtime dependencies | A test reads `pyproject.toml`; CI installs the wheel into a clean venv and fails if anything else appears |

These run on every push, every pull request, and daily. They are checked
properties, not promises — if one stops being true the build goes red.

Zero dependencies is the load-bearing one: a dependency tree is the usual way a
developer tool gains the ability to phone home, and you cannot audit one package,
you audit all of them forever. Full detail in
[docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md).

Reports contain file paths, line numbers, and **parameter names** from
signatures — never argument values or source text. A test enforces that.

## Install

```bash
uvx kiff-scan scan .          # no install
pipx install kiff-scan        # or a persistent CLI
pip install kiff-scan         # or into a venv
```

Python 3.10+. Nothing else.

## CI

```yaml
name: kiff-scan
on: [pull_request]

permissions:
  pull-requests: write     # sticky comment
  security-events: write   # SARIF upload
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kiff/kiff-scan@v0.2.0
```

Posts a sticky pull request comment, uploads SARIF to your Security tab, and
**does not fail the build by default**. Once you have triaged a baseline:

```yaml
      - uses: kiff/kiff-scan@v0.2.0
        with:
          fail-on: high
```

Pin the exact tag. A moving `v1` tag will be published once the interfaces stop
changing; until then a floating reference would silently change behaviour under
you.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage error (bad arguments, missing path, unusable config) |

The CLI defaults to `--fail-on medium`; the Action defaults to `none`. That
difference is deliberate. The CLI's exit code is its only machine-readable
signal, and a scanner that reports seven unguarded money-moving actions and exits
0 produces exactly the false assurance this tool exists to remove. The Action has
its own reporting surface, so it stays soft while a team triages.

## Commands

```bash
kiff-scan scan .                          # scan (also: kiff-scan .)
kiff-scan explain app/tools.py:47         # the analysed path behind one finding
kiff-scan scan . --format json            # machine-readable
kiff-scan scan . --format sarif           # GitHub code scanning
kiff-scan scan . --format markdown        # paste into an issue or PR
kiff-scan scan . --show-unsupported       # list files that could not be analysed
kiff-scan scan . --output report.json     # write to a file
```

## What it does not establish

A clean scan means **no supported path was identified** — not that your code is
safe. Specifically, kiff-scan does not establish that:

- an attacker can externally reach the agent
- no guard exists outside the analysed function
- exploitation is practical, or the operation irreversible
- any finding is a vulnerability

And it does not look at runtime behaviour, network configuration, prompt
injection, or any language other than Python. Decision detection uses **lexical
precedence, not control flow**, so a guard inside `if not force:` is credited
even though a caller can skip it; a guard is recognised **by name, not by
behaviour**, so an `authorize()` that always returns `True` clears a finding; and
calls are followed only **within a module** (up to four hops), so a destructive
call one *import* away is missed — on multi-module MCP servers this is the
largest remaining source of false negatives. Every limitation is listed in
[docs/COVERAGE.md](./docs/COVERAGE.md), including the ones we have not fixed.

## How accurate is it?

On ten public agent repositories, pinned at exact commits, with hand-labelled
expected findings. The bench scores what a user is asked to review: findings at
`medium` or above, in product code. Repositories where the scanner is **known to
miss** are included on purpose.

| repo | files | reported | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|---|
| strands-agents/tools | 72 | 4 | 4 | 0 | 0 | 1.00 | 1.00 |
| pydantic-ai (examples) | 48 | 0 | 0 | 0 | 0 | – | – |
| browser-use | 169 | 0 | 0 | 0 | 0 | – | – |
| smolagents | 18 | 0 | 0 | 0 | 0 | – | – |
| agno (human_in_the_loop) | 11 | 0 | 0 | 0 | 0 | – | – |
| awslabs/mcp (iam-mcp-server) | 13 | 6 | 6 | 0 | 0 | 1.00 | 1.00 |
| awslabs/mcp (ecs-mcp-server) | 91 | 0 | 0 | 0 | **2** | – | 0.00 |
| awslabs/mcp (eks-mcp-server) | 36 | 0 | 0 | 0 | **2** | – | 0.00 |
| awslabs/mcp (aws-api-mcp-server) | 67 | 0 | 0 | 0 | **1** | – | 0.00 |
| OpenHands/software-agent-sdk (tools) | 93 | 1 | 1 | 0 | **1** | 1.00 | 0.50 |
| **total** | **618** | **11** | **11** | **0** | **6** | **1.00** | **0.65** |

Reproduce with `python bench/run.py`. Labels are in `bench/expected/*.json`,
each with a `why` naming the call that justifies it.

**Read this honestly.** Precision is measured on eleven true findings, so 1.00
means "no known false positive in the labelled set", not "always right".
Recall is 0.65 because six labelled findings are not reached, and all six are
the same gap: the destructive call lives **in another module** — ECS's
`delete_stack` behind `api/delete.py`, EKS's Kubernetes calls behind
`k8s_apis.py`, `call_aws` executing in `core/aws/service.py`, OpenHands'
`Popen` behind a terminal factory. Cross-module following is the next thing
to build, and this table is how you will know when it lands. Two Strands
tools (`speak`, `file_read`) are reported at `low` — a fixed program with
model-controlled arguments, not a shell — and are counted but not scored; so
are OpenHands' `glob`/`grep` executors (`rg`) and LangChain's `grep_search`.

Against the previous release on the same trees:

| repo | 0.1.1 | now | what changed |
|---|---|---|---|
| strands-agents/tools | 12 | 4 + 2 low | 10 false positives removed; **both canonical dangerous tools now found** — the PTY shell reaching `os.execvp` and the REPL reaching `exec()` were previously missed entirely; `say` and `git` demoted to fixed-program, low |
| pydantic-ai (full repo) | 10 | 0 + 7 in tests | every product finding was `agent.run()` matched as shell execution; the seven that remain are `issue_refund` helpers in unit tests, listed but set aside |
| browser-use | 2 | 0 | `select_dropdown` matched because "drop" is a substring of "dropdown" |
| agno (full repo) | 24 | 0 + 18 in cookbook | HITL examples now cleared by `requires_confirmation=True`; the rest are cookbook code, set aside |
| awslabs/mcp (full repo) | 61 | 21 | ~40 docstring matches on read-only tools removed; glue `delete_table` and route53 record changes newly found through `mcp.tool(...)(fn)` registration |

Fewer findings is only an improvement if the remaining ones are more correct.
Here the count fell **and** the two tools the scanner most obviously should
have caught started being caught.

## What it will not flag

Deliberately, with regression tests for each:

- `agent.run()`, `chain.run()`, `client.call()` — delegation, not execution.
  Execution requires an execution receiver (`subprocess`, `os`, `asyncio`,
  `pexpect`, `pty`) or an explicit `shell=True`.
- `Console().capture()` — rich's output buffer, not a payment capture.
- `select_dropdown()` — identifiers are matched on whole tokens, so "drop" is a
  token of `drop_database` and is not a token of `dropdown`.
- `get_*`, `list_*`, `describe_*`, `check_*` — a read-only name vetoes a
  *declared* finding, though an observed `delete_table()` in the body still
  reports, because a read-only name in front of a destructive call is worth
  surfacing rather than believing.
- `@app.task` in a repo with no agent framework imported — that is a Celery
  job, not a tool.
- `subprocess.run(["say", text])` as a shell — a constant, non-interpreter
  program with model-controlled arguments is reported at `low`, because the
  model chooses what is said, not what runs. `["python3", "-c", code]`,
  `["bash", ...]`, `["crontab", ...]` or `shell=True` stay `high`.
- Findings under `tests/`, `examples/`, `cookbook/`, `docs/` as headline
  results — they are scanned and listed, but set aside from the totals, the
  "Most exposed" line and the exit code. `--include-tests` counts them.

## When a tool contradicts itself

A tool that declares `readOnlyHint=True` and then calls something destructive
gets its own section, because the accusation comes from the author's own
metadata rather than from this scanner's vocabulary:

```
  ANNOTATION MISMATCH (1)

    warehouse.py:14  inspect_table()
      declares:  readOnlyHint=True
      but:       calls delete_table()
```

The same reading works in the other direction: `requires_confirmation=True`
(agno), `needs_approval=True` (OpenAI Agents SDK), `external_execution=True`
and MCP `ToolAnnotations(readOnlyHint=True)` are all treated as decision
evidence, so a tool your framework already gates is not reported as ungoverned.

## Found a case where it is wrong?

That is the most useful bug report this project can get. In scope: a sink it
misses, a recognised guard it fails to honour, a finding on code with no
model-controlled input, or any case where it reports clean when it should not.
Accepted cases become permanent test fixtures, credited by handle. Known misses
stay on the list even before they are fixed — a challenge list showing only
fixed cases is a trophy cabinet.

## Where this comes from

kiff-scan is the diagnostic half of [KIFF](https://github.com/kiff/kiff): the
scanner reads the code, the runtime guard listens at execution. It is a
standalone tool and depends on nothing from KIFF — no account, no runtime, no
adoption. Use it and stop using it without touching anything else.

For a state-dependent finding, the remediation is a decision boundary that
evaluates live state before the action runs, and KIFF is one way to build that.
Your own state-aware check is another, and kiff-scan will recognise it.

## License

MIT — see [LICENSE](./LICENSE).

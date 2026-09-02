# kiff-scan

[![ci](https://github.com/kiff/kiff-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/kiff/kiff-scan/actions/workflows/ci.yml)
[![claims: machine-verified](https://github.com/kiff/kiff-scan/actions/workflows/verify-claims.yml/badge.svg)](https://github.com/kiff/kiff-scan/actions/workflows/verify-claims.yml)
[![PyPI](https://img.shields.io/pypi/v/kiff-scan)](https://pypi.org/project/kiff-scan/)
[![Python](https://img.shields.io/pypi/pyversions/kiff-scan)](https://pypi.org/project/kiff-scan/)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](./pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

> **What can your AI agent do without asking?**

kiff-scan finds Python functions that are callable by a model and reach an
action that deletes data, deploys, moves money, rotates a credential, or runs a
shell, with nothing on the path that can refuse.

```bash
uvx kiff-scan scan .
```

No install, no account, no config. Zero dependencies, no network code, and it
never executes the code it reads. All three are CI tests, not claims.

Need to show what is governed, what is not, and why? Generate an evidence-backed
assessment for an engineering or governance review:

```bash
uvx kiff-scan evidence . --format html --output kiff-report.html
```

The assessment turns the same source evidence into a readiness result, hard
blockers, a six-dimension governability scorecard, an action register, and a
prioritized remediation plan. Missing evidence is marked `not evidenced` or
`not assessable`; it is never converted into a pass. See
[Agent governability assessment](./docs/ASSESSMENT.md).

## Output

Run against [awslabs/mcp](https://github.com/awslabs/mcp)'s IAM server at
`e9f2439`:

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

## Why an auth check is not enough

Seven of the eight consequence categories are marked state-dependent. A rollback
to a broken revision, a failover to a region you already failed over to, a
`DROP` against the live database instead of the drained replica, a refund issued
twice before the first settles: each passes every role check you can write, and
each is wrong because of when it ran, not who asked.

For those, "add an authorization check" is the wrong fix. The scanner says so
instead of implying the check would have been enough.

## Accuracy

Ten public repositories, pinned at exact commits, findings labelled by hand:

| | |
|---|---|
| Files | 618 |
| Scored findings | 11 |
| Precision | 1.00 |
| Recall | 0.65 |

```bash
python bench/run.py
```

Recall is 0.65 because six labelled findings are not reached. All six are the
same gap: the destructive call lives in another module. The benchmark includes
four repositories where that gap is known to bite, so the number can go down as
well as up.

Read the precision honestly. Eleven scored findings is a small set, and four of
the ten repositories correctly report nothing, which does not test precision at
all. Labels are in `bench/expected/`, each naming the call that justifies it.

Against the previous release on identical trees:

| repo | 0.1.1 | 0.2.0 |
|---|---|---|
| strands-agents/tools | 12 findings, 10 wrong, both dangerous tools missed | 4, all correct, both found |
| pydantic-ai | 3, all `agent.run()` | 0 |
| browser-use | 2, both `select_dropdown` | 0 |
| agno (human_in_the_loop) | 1, ignoring its own confirmation flag | 0 |
| awslabs/mcp (IAM) | 6, correct | 6, correct |

## What it will not flag

Each has a regression test:

* `agent.run()`, `chain.run()`, `client.call()`. Execution needs an execution
  receiver (`subprocess`, `os`, `asyncio`, `pexpect`, `pty`) or `shell=True`.
* `Console().capture()`. That is rich's output buffer, not a payment capture.
* `select_dropdown()`. Names match on whole tokens, so `drop` is a token of
  `drop_database` and is not a token of `dropdown`.
* `get_*`, `list_*`, `check_*` when the finding comes from the name alone. An
  observed `delete_table()` in the body still reports.
* `@app.task` in a repo that imports no agent framework. That is a Celery job.
* `subprocess.run(["say", text])` reports at low, not high. A fixed program with
  model-controlled arguments is not a shell.
* Findings under `tests/`, `examples/`, `cookbook/`, `docs/` are listed but not
  counted. Pass `--include-tests` to count them.

## What it reads from your framework

A tool that declares `requires_confirmation=True` (agno), `needs_approval=True`
(OpenAI Agents SDK), `external_execution=True`, or MCP
`ToolAnnotations(readOnlyHint=True)` is treated as governed. Your framework
already gates it.

The reverse is a finding of its own:

```
  ANNOTATION MISMATCH (1)

    warehouse.py:14  inspect_table()
      declares:  readOnlyHint=True
      but:       calls delete_table()
```

The tool's own metadata is the accuser.

## Your code does not leave your machine

| Property | How it is enforced |
|---|---|
| No network code anywhere | A test rejects any import of `socket`, `ssl`, `http`, `urllib`, `requests`, `httpx`, `aiohttp` in every module |
| No telemetry | Same gate, plus a check for analytics SDK names |
| No socket opened during a scan | The socket constructor is replaced with one that fails the test, then a real scan runs |
| Works with networking off | A CI job drops all outbound traffic and runs the suite |
| Never executes your code | A test plants a file that would create a sentinel on import; the sentinel must not exist after scanning |
| Read-only | A test intercepts `open()` and fails on any write during a scan |
| Zero runtime dependencies | A test reads `pyproject.toml`; CI installs the wheel into a clean venv and fails if anything else appears |

These run on every push, every pull request, and daily. Reports contain file
paths, line numbers, and parameter names from signatures, never argument values
or source text. A test enforces that too.

Detail in [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md).

## Install

```bash
uvx kiff-scan scan .          # no install
uvx kiff-scan evidence .        # management-ready Markdown evidence report
pipx install kiff-scan        # or
pip install kiff-scan
```

Python 3.10+. In CI:

```yaml
- uses: kiff/kiff-scan@v0.2.0
  with:
    path: .
    fail-on: high
```

## Limits

* Python only. Other languages are reported as unsupported, never counted as
  clean.
* Calls are followed within a module, up to four hops. A destructive call one
  import away is missed. This is the largest source of false negatives.
* Lexical precedence, not control flow. A guard inside `if not force:` is
  credited even though a caller can skip it.
* Guards are recognised by name. An `authorize()` that always returns `True`
  clears a finding.
* `Agent(tools=[fn])` list registration and JSON-schema dispatch tables are not
  resolved.

A clean scan means no supported path was found. It is not evidence the code is
safe. Full list in [docs/COVERAGE.md](./docs/COVERAGE.md).

## Help build the data

The benchmark is a starting point, not a result. Ten repositories and eleven
scored findings is enough to catch a regression and not enough to characterise
how this behaves across the ecosystem.

Useful contributions, in rough order of value:

1. **A repository where it is wrong.** A missed sink, a false positive, a guard
   it should have honoured, or a clean result on code that is not. Open an issue
   with the repo, the commit, and the function. Accepted cases become fixtures.
2. **A framework it does not understand.** If your tools are registered in a
   shape that is not in [docs/COVERAGE.md](./docs/COVERAGE.md), that is a gap
   worth a fixture even before it is fixed.
3. **A labelled repository for `bench/`.** Add an entry to `bench/repos.json`
   with a pinned commit and a `bench/expected/<name>.json` where every label
   says which call justifies it. Repositories where the scanner does badly are
   more useful than ones where it does well.
4. **Numbers from your own codebase.** Findings before and after, how many you
   agreed with, what it missed. Aggregate counts are useful even without the
   source.

Known misses stay on the list before they are fixed. A challenge list showing
only fixed cases is a trophy cabinet.

## Docs

* [User guide](./docs/GUIDE.md). Reading a report, `explain`, CI, config,
  suppressions, exit codes.
* [Assessment](./docs/ASSESSMENT.md). Readiness rules, evidence states, report
  formats, and claim boundaries.
* [Coverage](./docs/COVERAGE.md). Every registration shape and sink, supported
  and not.
* [Threat model](./docs/THREAT_MODEL.md).

## Where this comes from

I build [KIFF](https://kiff.dev), a runtime for the decision this scanner asks
for. The scanner does not need it, does not talk to it, and works the same
without it. Guard detection is vendor-neutral: your own `authorize()` clears a
finding exactly as anything else does.

## License

MIT.

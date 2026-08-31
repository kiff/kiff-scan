# kiff-scan

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

Run against a sample SRE agent (`tests/fixtures/ungoverned_ops.py` in this repo):

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
      - uses: kiff/kiff-scan@v1
```

Posts a sticky pull request comment, uploads SARIF to your Security tab, and
**does not fail the build by default**. Once you have triaged a baseline:

```yaml
      - uses: kiff/kiff-scan@v1
        with:
          fail-on: high
```

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
precedence, not control flow**, so a conditional guard is credited; and it works
at **function scope**, so a guard in a caller or an unrecognised middleware is
missed, producing false positives. Every limitation is listed in
[docs/COVERAGE.md](./docs/COVERAGE.md), including the ones we have not fixed.

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

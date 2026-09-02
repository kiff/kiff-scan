# User guide

How to run kiff-scan, read what it prints, and wire it into a project.

## Contents

* [Running a scan](#running-a-scan)
* [Generating a governability assessment](#generating-a-governability-assessment)
* [Reading a report](#reading-a-report)
* [Confidence: call vs declared vs annotated](#confidence-call-vs-declared-vs-annotated)
* [Decision evidence](#decision-evidence)
* [Severity](#severity)
* [explain](#explain)
* [Test and example code](#test-and-example-code)
* [Output formats](#output-formats)
* [Exit codes](#exit-codes)
* [CI](#ci)
* [Configuration](#configuration)
* [Teaching it your own vocabulary](#teaching-it-your-own-vocabulary)
* [What to do about a finding](#what-to-do-about-a-finding)

## Running a scan

```bash
uvx kiff-scan scan .                  # a directory tree
uvx kiff-scan scan src/tools.py       # one file
uvx kiff-scan scan . --fail-on medium # exit 1 at medium or above
```

The scanner parses Python with the standard library's `ast`. It never imports
or executes the file, so pointing it at a repository you do not trust is safe.

Files it cannot parse are reported as unsupported. They are never counted as
clean, because "I could not read this" and "this is fine" are different
answers and conflating them is how a scanner produces false confidence.

## Generating a governability assessment

```bash
uvx kiff-scan assess .
uvx kiff-scan assess . --format json --output kiff-report.json
uvx kiff-scan assess . --format html --output kiff-report.html
```

`assess` runs the same analyzer as `scan`; it does not use a second or broader
detector. It organizes the findings into a technical-governance report with a
readiness result, hard blockers, evidence states, an action register, and a
remediation plan. See [Assessment](./ASSESSMENT.md) for the rubric and claim
boundary.

An assessment exits 1 only for `NOT READY`, meaning a hard blocker was found.
`CONDITIONAL` exits 0 so teams can adopt reporting before every evidence gap is
closed. Usage errors remain exit 2.

## Reading a report

```
  Most exposed: server.py:431  delete_user()
    Reachable by:            @tool
    Consequence:             Secrets / identity  (calls delete_access_key())
    Severity:                high
    Match confidence:        call
    Decision on path:        none found on the analysed path
    Model-controlled inputs: user_name, force, confirmed
```

Line by line:

**Reachable by** is how a model can invoke this function. A decorator
(`@tool`, `@mcp.tool`, `@agent.tool_plain`), a tool base class
(`BaseTool subclass (_run)`), a registration call
(`registered via StructuredTool.from_function()`), or a module-level
`TOOL_SPEC declaration`. The report prints the route that actually applied, so
it never claims `@tool` when the code used `@function_tool`.

**Consequence** is the category and the specific call that produced it. When the
call is not in the function body, the chain is printed:

```
calls _create_schedule() which calls _ensure_scheduler_role()
  which calls attach_role_policy()
```

**Model-controlled inputs** are parameter *names* from the signature. Never
argument values, never source text.

## Confidence: call vs declared vs annotated

| Confidence | Means | Severity cap |
|---|---|---|
| `call` | A recognised SDK call was found in the body or reachable through module-local helpers | none |
| `declared` | The classification comes from the function's name or its docstring summary. No such call was observed | capped at medium |
| `annotated` | The tool declares `destructiveHint=True` and nothing else was found | capped at medium |

`declared` exists because agent tools are often thin shims that delegate to a
service the scanner cannot see. Dropping them would report clean on an agent
that can plainly drop a database. Treating them as equally certain would be
dishonest, so they are labelled and capped instead.

A read-only name prefix (`get_`, `list_`, `describe_`, `check_`, and similar)
suppresses a `declared` finding. It does not suppress a `call` finding: a
function called `get_config` that calls `delete_table()` is worth surfacing.

## Decision evidence

Every finding says what was found on the path, and how precisely.

| Evidence | Meaning |
|---|---|
| `call_before_sink` | A guard call appears in the same function, before the sink. Credited |
| `decorator` | A recognised guard decorator wraps the function. Credited |
| `framework_approval` | The tool decorator declares a human-in-the-loop flag. Credited |
| `module_hook` | A guard is installed over every tool at agent construction. Credited |
| `call_after_sink` | A guard call exists but only after the sink. Reported, not credited |
| `none` | Nothing found on the analysed path |

Ordering is lexical, and same-line cases compare column offsets, so
`if authorize(x): delete(x)` is credited.

Recognised framework flags: `requires_confirmation=True`,
`requires_user_input=True`, `needs_approval=True`, `external_execution=True`,
and MCP `ToolAnnotations(readOnlyHint=True)`.

A guard is recognised by *name*, not by behaviour. An `authorize()` that always
returns `True` clears a finding. This is a real limit, not an oversight: proving
what a function does requires analysis this tool deliberately does not do.

## Severity

Comes from the consequence category, then adjusted:

* `declared` and `annotated` never exceed medium.
* A fixed program with model-controlled arguments (`subprocess.run(["say", text])`)
  is low. The model chooses the arguments, not the program.
* An interpreter, `shell=True`, or an argv the model builds stays high.

## explain

```bash
kiff-scan explain src/tools.py:431
```

Prints the analysed path for one finding: the route, the chain to the sink, the
evidence, and what the category means. The `Next:` line at the end of a scan
gives you the exact command for the most exposed finding.

## Test and example code

Findings under `tests/`, `test_*.py`, `*_test.py`, `examples/`, `cookbook/` and
`docs/`, relative to the scan root, are listed separately and excluded from the
totals, from "Most exposed", and from the exit code.

A tool registered in a test is real reachability, so it is not hidden. It is
just not the first thing you should look at in your own repository.

```bash
kiff-scan scan . --include-tests    # count them
```

Note this is relative to the scan root. Scanning `examples/` directly sets
nothing aside, because nothing is under `examples/` relative to that root.

## Output formats

```bash
kiff-scan scan . --format json      # machine-readable
kiff-scan scan . --format sarif     # GitHub Security tab
kiff-scan scan . --format markdown  # PR comment
kiff-scan scan . --output report.json

kiff-scan assess . --format markdown
kiff-scan assess . --format json --output kiff-report.json
kiff-scan assess . --format html --output kiff-report.html
```

JSON fields worth knowing: `governed`, `confidence`, `decision_evidence`,
`state_dependent`, `annotation_mismatch`, `declared_annotations`,
`in_test_code`, `counted`.

Assessment JSON has its own versioned schema. Derived conclusions live under
`conclusion`, `dimensions`, and `hard_blockers`; the scanner facts supporting
them remain separate under `evidence`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above the threshold |
| 1 | Findings at or above the threshold |
| 2 | Usage error, or a path that does not exist |

The default threshold is `high` for the CLI. The GitHub Action defaults to
`high` as well; set `fail-on: low` to be strict.

## CI

```yaml
- uses: kiff/kiff-scan@v0.2.0
  with:
    path: .
    fail-on: high
    upload-sarif: true
```

The Action posts a sticky pull-request comment and uploads SARIF to the
Security tab. Pin the version tag: each tag installs the matching package
version, so an existing tag cannot change behaviour when a new release lands.

## Configuration

`kiff-scan.toml` or a `[tool.kiff-scan]` table in `pyproject.toml`:

```toml
[tool.kiff-scan]
exclude = ["vendor/**", "**/generated_*.py"]
exclude_dirs = ["third_party"]
fail_on = "medium"
include_tests = false
tool_decorators = ["my_tool", "register_capability"]
guards = ["check_entitlement", "require_change_ticket"]
```

## Teaching it your own vocabulary

Two lists matter most.

**`tool_decorators`** adds decorators that expose a function to a model. Use it
when your codebase wraps a framework in its own registration helper.

**`guards`** adds calls that count as a decision. Use it when your team's check
is not one of the recognised names. A guard cleared this way is reported as
cleared with the name that cleared it, so a reader can disagree.

Both are additive. Nothing recognised by default is removed.

## What to do about a finding

The question the scanner is asking is not "is this code bad". It is "if the
model picks the arguments, is there anything on the path that can say no".

Four answers, in rough order of preference:

1. **Add a decision before the call**, evaluated against the current state of
   the thing being acted on. For a state-dependent category this is the only
   answer that actually holds: check whether the database is a live primary
   before dropping it, whether the target revision is healthy before rolling
   back to it, whether the refund already settled.
2. **Declare the boundary your framework already provides.**
   `requires_confirmation=True`, `needs_approval=True`, or the equivalent. The
   scanner reads these and clears the finding.
3. **Mark it read-only if it is.** MCP `ToolAnnotations(readOnlyHint=True)` on a
   tool that genuinely only reads suppresses the finding. On a tool that
   reaches a destructive call it is reported as a contradiction instead.
4. **Decide it is fine and move on.** A scanner's job is to make the choice
   visible, not to make it for you. Add the tool to `exclude` if you do not want
   to see it again.

If you think the finding itself is wrong, that is the most useful issue you can
open. See the contribution section in the [README](../README.md).

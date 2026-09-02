# Agent governability assessment

`kiff-scan assess` turns scanner evidence into a technical-governance report
that can be reviewed by engineering, security, and AI governance teams.

```bash
uvx kiff-scan assess .
uvx kiff-scan assess . --format json --output kiff-report.json
uvx kiff-scan assess . --format html --output kiff-report.html
```

It answers a narrower and more defensible question than "is this agent safe?":

> What can this repository prove about whether consequential agent actions are
> governable, and what code-level evidence is missing?

## Evidence states

Every dimension carries one of four states:

| State | Meaning |
|---|---|
| `evidenced` | The supported scan found direct evidence for the conclusion |
| `partial` | Evidence covers only part of the relevant surface |
| `not_evidenced` | The dimension is relevant, but the recognized evidence was not found |
| `not_assessable` | The current analysis cannot prove or disprove the dimension |

`not assessable` is not a pass. It also is not automatically a failure. It is a
request for another source of evidence: runtime records, architecture review,
identity configuration, policy documentation, or manual validation.

## Dimensions

The report covers:

1. **Consequential action inventory.** Model-reachable tools, consequence
   categories, severity, state dependence, and paths to sinks.
2. **Pre-execution decision coverage.** Whether recognized decision evidence
   appears before each consequence.
3. **Operational-state grounding.** Which actions require current state and
   whether the scanner can establish that state is evaluated.
4. **Human authority.** Explicit framework-enforced confirmation or approval.
   A generic guard name is not treated as proof of independent human review.
5. **Identity and permission boundaries.** Whether actor identity and authority
   can be established from the scanned evidence.
6. **Traceability.** Whether durable decisions, receipts, events, and execution
   outcomes can be established.

The current release can inventory actions and classify decision evidence. It
can recognize explicit framework approval. It cannot yet prove live-state use,
runtime identity derivation, segregation of duties, or durable audit records;
those dimensions are reported honestly as `not assessable`.

## Readiness rules

The result is derived by deterministic rules. It is not a weighted marketing
score.

### NOT READY

At least one hard blocker exists:

- a high-severity consequential path has no recognized pre-execution decision;
  or
- a consequential tool contradicts its own `readOnlyHint=True` annotation.

Hard blockers cannot be averaged away by stronger evidence elsewhere.

### CONDITIONAL

No hard blocker was found, but at least one important dimension is partial, not
evidenced, or not assessable. This is the expected result when a repository has
code-level decision coverage but still needs runtime or organizational proof.

### READY WITHIN SCANNED SCOPE

Every required code-level dimension is evidenced and no hard blocker exists.
The phrase "within scanned scope" is mandatory: unsupported languages,
unfollowed module boundaries, and runtime behavior remain outside the claim.

## Report contents

Markdown and HTML reports contain:

- executive summary and readiness reason;
- hard blockers;
- governability scorecard;
- consequential-action register;
- evidence paths;
- contradictions and weak evidence;
- prioritized remediation;
- scope and claim boundary; and
- scanner version, schema version, timestamp, analyzed root, and repository
  commit when available.

JSON keeps derived conclusions separate from raw scanner evidence:

```text
conclusion / dimensions / hard_blockers / remediation
evidence.summary / evidence.actions / evidence.unsupported
```

The JSON schema starts at version 1. Breaking shape changes require a schema
version increase.

## What this is not

This report is not an AI Act, GDPR, SOC 2, ISO 27001, or internal-policy
certification. Static source analysis cannot establish organizational roles,
portfolio value, vendor risk, model quality, production drift, business
correctness, or whether a control actually operated at runtime.

Use it as the repeatable technical-evidence portion of a wider governance
diagnostic, not as a replacement for that diagnostic.

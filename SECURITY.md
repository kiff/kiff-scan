# Security policy

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the
Security tab of this repository. Please do not open a public issue for a
vulnerability.

Include the version, your platform and Python version, a minimal reproducing
input, and what you observed against what you expected.

We aim to acknowledge within three working days.

## What counts as a vulnerability here

kiff-scan is a static analyser that reads source files and writes a report. The
security-relevant failures are:

- **Any egress.** A code path that opens a network connection, or that transmits
  scanned content anywhere. There should be none; if you find one, that is a
  vulnerability, not a bug.
- **Executing analysed code.** The scanner must only parse. A path that imports,
  `eval`s, or otherwise runs the code under analysis is a vulnerability, because
  it turns pointing the tool at an untrusted repository into remote code
  execution.
- **Writing outside `--output`.** A scan must not modify the tree it reads.
- **Leaking source content into a report.** Reports carry paths, line numbers,
  and parameter names. Argument values or source text appearing in output is a
  data-handling defect.
- **Denial of service on hostile input.** A crafted source file that hangs the
  scanner or exhausts memory.

## What is a soundness bug, not a vulnerability

A missed finding or a false positive is a correctness issue. Please report it as
a normal issue — see the "Reporting a miss" section of
[docs/COVERAGE.md](./docs/COVERAGE.md). These matter a great deal, and a missed
finding is the most valuable bug report this project can receive, but they go
through the public tracker so the case can become a test fixture.

## Supported versions

The latest minor release receives fixes. This project is pre-1.0; expect fixes
to land in a new release rather than as backports.

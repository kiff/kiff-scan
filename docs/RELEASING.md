# Releasing

Publishing uses **PyPI Trusted Publishing** (OIDC). No API token is stored in
this repository: PyPI verifies a short-lived credential minted by GitHub for this
specific workflow, repository, and environment. There is nothing to leak and
nothing to rotate.

## One-time setup

### 1. PyPI: add a pending publisher

Do this *before* the first upload, while the project does not exist yet.

PyPI → your account → **Publishing** → *Add a new pending publisher* → GitHub:

| Field | Value |
|---|---|
| PyPI Project Name | `kiff-scan` |
| Owner | `kiff` |
| Repository name | `kiff-scan` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Repeat on [test.pypi.org](https://test.pypi.org) with environment `testpypi` if
you want to rehearse.

The environment name must match exactly, or PyPI rejects the upload.

### 2. GitHub: create the environments

Repository → Settings → Environments → **New environment** → `pypi`, and again
for `testpypi`.

Add a required reviewer on `pypi` if you want a human approval gate before any
upload. Recommended: a release is irreversible, since PyPI does not allow
re-uploading a version once published.

## Releasing a version

```bash
# 1. Bump the version in pyproject.toml, and date the CHANGELOG entry.
#    The release workflow fails if the tag and pyproject version disagree.

# 2. Confirm the gates locally.
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
.venv/bin/kiff-scan scan . --fail-on low

# 3. Commit, tag, push.
git commit -am "release 0.1.0"
git tag v0.1.0
git push origin main --tags
```

Pushing the tag runs `release.yml`, which:

1. runs the full suite plus the security gates, and a clean self-scan
2. builds the sdist and wheel
3. fails if the tag does not match the packaged version
4. fails if installing the built wheel pulls in **any** dependency
5. publishes to PyPI with PEP 740 provenance attestations
6. creates the GitHub release with the artifacts attached

Step 4 is the one that keeps the README honest: the zero-dependency claim is
re-verified against the actual artifact being shipped, not against source.

## Rehearsing on TestPyPI

Actions → **release** → *Run workflow* → target `testpypi`. Then:

```bash
pipx run --index-url https://test.pypi.org/simple/ kiff-scan --version
```

## After publishing

```bash
# Confirm the published artifact installs clean and pulls in nothing.
python -m venv /tmp/verify && /tmp/verify/bin/pip install kiff-scan
/tmp/verify/bin/pip list          # expect only kiff-scan and pip
/tmp/verify/bin/kiff-scan --version

# Confirm the headline install path works.
uvx kiff-scan scan .
```

## Versioning

Semantic versioning. Pre-1.0, a minor bump may change detector behaviour, since
adding a sink or a guard pattern changes what a scan reports — which is a
behaviour change for anyone gating CI on the exit code.

The GitHub Action is referenced by exact tag (`kiff/kiff-scan@v0.1.0`). A moving
`v1` tag will be introduced at 1.0, once the inputs and the finding shape are
stable; publishing a floating tag before then would silently change behaviour in
other people's pipelines.

"""Gate: the zero-runtime-dependency claim is read from packaging metadata.

The README's central credibility claim is that installing kiff-scan adds nothing
to your dependency tree. This test reads `pyproject.toml` so the claim cannot
drift away from the packaging metadata, and reads it with the standard library
only -- a dependency-checking test that itself needed a dependency would be
self-defeating.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    tomllib = None

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _load_pyproject() -> dict:
    if tomllib is None:
        pytest.skip("tomllib requires Python 3.11+; the CI matrix covers this gate")
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def test_pyproject_exists():
    assert PYPROJECT.is_file()


def test_zero_runtime_dependencies():
    deps = _load_pyproject()["project"].get("dependencies", [])
    assert deps == [], (
        f"kiff-scan declares runtime dependencies {deps}. Zero dependencies is the "
        "property that lets a security team run this against a codebase that has "
        "adopted nothing; adding one is a product decision, not a refactor."
    )


def test_optional_dependencies_are_dev_only():
    """Extras must never be required to run a scan."""
    extras = _load_pyproject()["project"].get("optional-dependencies", {})
    assert set(extras) <= {"dev"}, f"unexpected extras: {sorted(set(extras) - {'dev'})}"


def test_declared_python_support_is_real():
    requires = _load_pyproject()["project"]["requires-python"]
    assert requires == ">=3.10"


def test_version_matches_package():
    from kiff_scan import __version__

    assert _load_pyproject()["project"]["version"] == __version__


def test_package_imports_without_any_third_party_module():
    """Import the package with third-party paths removed from sys.path.

    If kiff_scan needed anything outside the standard library, this fails.
    """
    import importlib

    src = str(REPO_ROOT / "src")
    stdlib_only = [p for p in sys.path if "site-packages" not in p and "dist-packages" not in p]

    saved_path = list(sys.path)
    saved_modules = {k: v for k, v in sys.modules.items() if k.startswith("kiff_scan")}
    try:
        for name in list(saved_modules):
            del sys.modules[name]
        sys.path[:] = [src] + stdlib_only
        module = importlib.import_module("kiff_scan")
        assert module.__version__
    finally:
        sys.path[:] = saved_path
        sys.modules.update(saved_modules)

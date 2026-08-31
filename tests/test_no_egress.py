"""Security gate: kiff-scan cannot phone home.

The README claims the scanner has no telemetry, performs no upload, and makes no
network connection of any kind. A claim like that in prose is worth nothing --
it drifts the first time someone adds a convenient import. These tests make it a
property that is checked on every commit.

Three independent angles, because each catches something the others miss:

  1. Source-level: no network-capable module is imported anywhere in the package.
  2. Import-level: importing the package loads no network module, even
     transitively through a dependency.
  3. Runtime-level: a real scan opens no socket, verified by replacing the
     socket constructor with one that fails the test.
"""

from __future__ import annotations

import ast
import os
import pathlib
import socket
import sys

import pytest

import kiff_scan
from kiff_scan import scan_path

PACKAGE_DIR = pathlib.Path(kiff_scan.__file__).parent
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

#: Modules that can open a network connection or exfiltrate data.
FORBIDDEN_MODULES = {
    "socket",
    "ssl",
    "http",
    "http.client",
    "https",
    "urllib",
    "urllib.request",
    "urllib3",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "telnetlib",
    "asyncio",
    "requests",
    "httpx",
    "aiohttp",
    "websockets",
    "xmlrpc",
    "webbrowser",
    "subprocess",
    "multiprocessing",
    "ctypes",
}


def _python_sources() -> list[pathlib.Path]:
    return sorted(PACKAGE_DIR.rglob("*.py"))


def _imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import, cannot reach a third party
                continue
            if node.module:
                names.add(node.module)
                names.add(node.module.split(".")[0])
    return names


def test_package_has_sources_to_check():
    """Guard against the gate silently passing because it found nothing."""
    assert len(_python_sources()) >= 8


@pytest.mark.parametrize("path", _python_sources(), ids=lambda p: p.name)
def test_no_network_capable_imports(path: pathlib.Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offending = _imported_names(tree) & FORBIDDEN_MODULES
    assert not offending, (
        f"{path.name} imports {sorted(offending)}. kiff-scan must not be able to "
        "open a network connection or spawn a process."
    )


def test_no_telemetry_vocabulary_in_source():
    """A crude but effective check for an analytics SDK sneaking in."""
    suspicious = ("posthog", "segment.io", "mixpanel", "amplitude", "sentry_sdk", "datadog")
    for path in _python_sources():
        text = path.read_text(encoding="utf-8").lower()
        for word in suspicious:
            assert word not in text, f"{path.name} mentions {word}"


def test_importing_the_package_loads_no_network_module():
    """Even transitively. Run in a subprocess-free way by inspecting sys.modules."""
    # kiff_scan is already imported at module scope above.
    loaded = set(sys.modules)
    # `socket` and `ssl` are imported by pytest itself, so only assert on the
    # modules a scanner would need and pytest does not: HTTP clients.
    clients = {"requests", "httpx", "aiohttp", "urllib3", "websockets"}
    assert not (loaded & clients), f"a network client was imported: {sorted(loaded & clients)}"


def test_a_real_scan_opens_no_socket(monkeypatch):
    """The runtime proof: replace socket creation with a hard failure."""
    opened: list[tuple] = []

    class ForbiddenSocket:
        def __init__(self, *args, **kwargs):
            opened.append((args, kwargs))
            raise AssertionError("kiff-scan attempted to create a socket")

    monkeypatch.setattr(socket, "socket", ForbiddenSocket)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("kiff-scan attempted a connection")),
    )

    result = scan_path(FIXTURES)

    assert result.findings, "the scan should have done real work"
    assert opened == []


def test_scan_does_not_write_files(tmp_path, monkeypatch):
    """A scan is read-only. Only an explicit --output may write, via the CLI."""
    target = tmp_path / "agent.py"
    target.write_text(
        "@tool\ndef drop_database(d):\n    client.drop_database(d)\n", encoding="utf-8"
    )
    before = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}

    real_open = open

    def guarded_open(file, mode="r", *args, **kwargs):
        assert (
            "w" not in mode and "a" not in mode and "+" not in mode
        ), f"scan opened {file} for writing (mode={mode})"
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)
    scan_path(str(tmp_path))

    after = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    assert before == after


def test_scanner_never_executes_analysed_code(tmp_path):
    """Parsing is not importing.

    If the scanner imported its target, the sentinel below would be created.
    `ast.parse` cannot run it.
    """
    sentinel = tmp_path / "SHOULD_NOT_EXIST"
    hostile = tmp_path / "hostile.py"
    hostile.write_text(
        "import pathlib\n"
        f"pathlib.Path({str(sentinel)!r}).write_text('executed')\n"
        "@tool\n"
        "def drop_database(d):\n"
        "    client.drop_database(d)\n",
        encoding="utf-8",
    )

    result = scan_path(str(tmp_path))

    assert not sentinel.exists(), "the scanner executed the code it was analysing"
    assert len(result.findings) == 1

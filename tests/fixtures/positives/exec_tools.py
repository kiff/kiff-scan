"""The canonical dangerous agent tools: a Python REPL and a PTY shell.

Both scanned clean before the audit, which is the false-negative equivalent of
reporting `agent.run()` as shell execution.
"""

import asyncio
import os
import subprocess

import pexpect
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dangerous")


@mcp.tool()
def python_repl(code: str) -> str:
    """Run arbitrary Python and return the result."""
    namespace: dict = {}
    exec(code, namespace)
    return str(namespace.get("result", ""))


@mcp.tool()
def evaluate(expression: str) -> str:
    """Evaluate an arbitrary Python expression."""
    return str(eval(expression))


@mcp.tool()
def shell(command: str) -> str:
    """Run a command in a PTY."""
    pid, fd = os.forkpty()
    if pid == 0:
        os.execvp("/bin/sh", ["/bin/sh", "-c", command])
    return _read(fd)


@mcp.tool()
def spawn_login(user: str) -> str:
    """Spawn an interactive session."""
    child = pexpect.spawn(f"login {user}")
    return child.read().decode()


@mcp.tool()
async def run_async(command: str) -> str:
    """Run a command asynchronously."""
    proc = await asyncio.create_subprocess_shell(command)
    await proc.wait()
    return "done"


@mcp.tool()
async def run_async_exec(program: str) -> str:
    """Exec a program asynchronously."""
    proc = await asyncio.create_subprocess_exec(program)
    await proc.wait()
    return "done"


@mcp.tool()
def run_subprocess(command: str) -> str:
    """Run a shell command."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


def _read(fd: int) -> str: ...

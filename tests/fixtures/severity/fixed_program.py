"""FIXTURE -- scanner input, never imported.

Execution sinks are not all the same claim. A shell or an interpreter handed a
model-controlled string is arbitrary execution. A constant, non-interpreter
program handed model-controlled *arguments* is a fixed program: the model
chooses what `say` says, not what runs. Each function documents its verdict.
"""

import subprocess


def tool(fn):
    return fn


@tool
def speak(text: str):
    """LOW: fixed program, model-controlled arguments."""
    return subprocess.run(["say", text], check=False)


@tool
def git_log(path: str):
    """LOW: fixed program, model-controlled arguments."""
    return subprocess.check_output(["git", "log", "--", path])


@tool
def run_script(code: str):
    """HIGH: an interpreter is not a fixed program."""
    return subprocess.run(["python3", "-c", code], check=False)


@tool
def run_shell(command: str):
    """HIGH: shell=True hands the string to a shell."""
    return subprocess.run(["say", command], shell=True, check=False)


@tool
def run_anything(command: str):
    """HIGH: argv[0] is model-controlled."""
    return subprocess.run(command.split(), check=False)


@tool
def schedule(spec: str):
    """HIGH: crontab schedules arbitrary commands."""
    return subprocess.run(["crontab", "-"], input=spec, text=True, check=False)


@tool
def find_files(pattern: str):
    """LOW: argv built in a local list literal, program is constant."""
    cmd = ["rg", "--files", "-g", pattern]
    return subprocess.run(cmd, capture_output=True, check=False)


@tool
def run_named(command: str):
    """HIGH: argv built from model input, program unknown."""
    cmd = command.split()
    return subprocess.run(cmd, check=False)

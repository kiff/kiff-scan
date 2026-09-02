"""FIXTURE -- scanner input, never imported.

OpenHands-style tools: a ToolExecutor subclass whose entry point is
__call__, with a generic base (`ToolExecutor[Action, Observation]`).
"""

import subprocess


class ToolExecutor:
    pass


class TerminalAction:
    pass


class TerminalObservation:
    pass


class TerminalExecutor(ToolExecutor[TerminalAction, TerminalObservation]):
    def __call__(self, action: TerminalAction) -> TerminalObservation:
        return subprocess.run(action.command, shell=True, check=False)

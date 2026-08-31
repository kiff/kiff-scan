"""Detectors: reachability, sinks, and decisions.

Each detector answers one question about a function, and the engine combines
them. A finding requires all three: the model can reach it, it does something
consequential, and nothing on the path can refuse it.
"""

from __future__ import annotations

__all__ = ["decisions", "reachability", "sinks"]

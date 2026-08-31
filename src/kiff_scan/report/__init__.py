"""Reporters. Each takes a ScanResult and returns a string; none writes files
or opens a network connection."""

from __future__ import annotations

__all__ = ["json_out", "pretty", "sarif"]

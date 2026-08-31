"""Configuration.

Read from `.kiff-scan.json` at the scan root, or an explicit `--config` path.
Everything is optional; an absent config file is not an error and is the
expected case for a first run.

Config exists so that a team can extend detection -- their own guard function
names, their own agent framework's tool decorator -- without forking the
scanner or waiting for a release. User-supplied vocabulary is merged with the
defaults and is never second-class: a guard named `acme_authorize` clears a
finding exactly as a built-in name would.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

__all__ = ["Config", "load_config", "CONFIG_FILENAME"]

CONFIG_FILENAME = ".kiff-scan.json"

#: Directory names never walked. Substring matching on the whole path would
#: wrongly skip a legitimate directory such as `src/git_tools/`, so matching is
#: done per path segment.
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        "node_modules",
        "site-packages",
        "dist",
        "build",
        ".eggs",
    }
)


@dataclass
class Config:
    """Effective scan configuration."""

    #: Extra guard/decision function names that clear a sink.
    guards: list[str] = field(default_factory=list)
    #: Extra decorator names that make a function agent-reachable.
    tool_decorators: list[str] = field(default_factory=list)
    #: Glob patterns (matched against the path relative to the scan root)
    #: excluded from the scan.
    exclude: list[str] = field(default_factory=list)
    #: Directory segment names to skip, added to DEFAULT_EXCLUDE_DIRS.
    exclude_dirs: list[str] = field(default_factory=list)

    @property
    def all_exclude_dirs(self) -> frozenset[str]:
        return DEFAULT_EXCLUDE_DIRS | set(self.exclude_dirs)


class ConfigError(Exception):
    """Raised when a config file exists but cannot be used.

    Deliberately fatal. Silently ignoring a malformed config would mean
    silently ignoring the exclusions and custom guards a team relies on, and
    then reporting findings they thought they had configured away.
    """


def _as_str_list(raw: object, key: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ConfigError(f"{CONFIG_FILENAME}: '{key}' must be a list of strings")
    return list(raw)


def load_config(root: str, explicit_path: str | None = None) -> Config:
    """Load config for a scan rooted at `root`.

    An explicit path that does not exist is an error; an auto-discovered file
    that does not exist is not.
    """
    if explicit_path:
        if not os.path.isfile(explicit_path):
            raise ConfigError(f"config file not found: {explicit_path}")
        path: str | None = explicit_path
    else:
        base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
        candidate = os.path.join(base, CONFIG_FILENAME)
        path = candidate if os.path.isfile(candidate) else None

    if path is None:
        return Config()

    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a JSON object")

    return Config(
        guards=_as_str_list(raw.get("guards"), "guards"),
        tool_decorators=_as_str_list(raw.get("tool_decorators"), "tool_decorators"),
        exclude=_as_str_list(raw.get("exclude"), "exclude"),
        exclude_dirs=_as_str_list(raw.get("exclude_dirs"), "exclude_dirs"),
    )

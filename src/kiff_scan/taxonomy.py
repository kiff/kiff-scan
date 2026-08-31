"""The consequence taxonomy.

Every finding is classified into exactly one consequence category. The field
that matters most here is `state_dependent`.

A conventional scanner asks: *is there an authorization check on this path?*
That question is necessary but not sufficient, and treating it as sufficient is
how a governed-looking system still destroys something. Many consequential
actions are fully authorized, in-plan, and executed by a principal who is
genuinely allowed to perform them -- and are catastrophic anyway, because their
safety depends on the *state of the world at the moment of execution*:

  - a rollback to a build that is itself broken
  - a failover to the region you have already failed over to
  - a DROP against a database that is live rather than the drained replica
  - a refund issued twice because the first one has not settled yet

Each of those is legitimate in one state and catastrophic in another. No
role check, signed plan, or API key can distinguish them, because the
difference is not *who* is asking or *what* they are asking for -- it is
*when*. Only a decision evaluated against live entity state can refuse them.

`state_dependent = True` marks the categories where that is the case. For
those, kiff-scan reports the absence of a state-aware decision, not merely the
absence of an authorization check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "Consequence",
    "CONSEQUENCES",
    "SEVERITY_ORDER",
    "SEVERITIES",
    "meets_threshold",
]


@dataclass(frozen=True)
class Consequence:
    """One consequence category."""

    id: str
    label: str
    severity: str
    state_dependent: bool
    why: str


def _c(
    id: str, label: str, severity: str, state_dependent: bool, why: str
) -> tuple[str, Consequence]:
    return id, Consequence(id, label, severity, state_dependent, why)


CONSEQUENCES: Final[dict[str, Consequence]] = dict(
    [
        _c(
            "DATA_LOSS",
            "Data loss",
            "high",
            True,
            "Dropping or deleting stored data is irreversible, and whether a given "
            "target is safe to drop depends on whether it is live.",
        ),
        _c(
            "COMPUTE",
            "Compute teardown",
            "high",
            True,
            "Terminating compute is safe on a drained node and an outage on a "
            "serving one. The call site cannot tell the difference.",
        ),
        _c(
            "DEPLOYMENT",
            "Deploy / rollback",
            "medium",
            True,
            "A rollback is only safe if the target revision is good, which is a "
            "fact about live state rather than about the request.",
        ),
        _c(
            "NETWORK",
            "Traffic / failover",
            "high",
            True,
            "Shifting traffic depends on where traffic currently is; a failover to "
            "the active region is an outage.",
        ),
        _c(
            "IDENTITY",
            "Secrets / identity",
            "high",
            True,
            "Rotating or granting credentials changes who can act next, and its "
            "safety depends on what is currently holding the old credential.",
        ),
        _c(
            "DATABASE",
            "Schema / migration",
            "high",
            True,
            "A migration is safe against one schema version and destructive " "against another.",
        ),
        _c(
            "MONEY",
            "Money movement",
            "high",
            True,
            "Whether a payment or refund is correct depends on the settlement "
            "state of the order it refers to.",
        ),
        _c(
            "EXECUTION",
            "Shell / execution",
            "high",
            False,
            "Arbitrary command execution reachable from model-controlled input is "
            "unsafe regardless of state; this one is a plain authorization and "
            "input-handling problem.",
        ),
    ]
)

SEVERITIES: Final[tuple[str, ...]] = ("none", "low", "medium", "high")

SEVERITY_ORDER: Final[dict[str, int]] = {name: i for i, name in enumerate(SEVERITIES)}


def meets_threshold(severity: str, threshold: str) -> bool:
    """True when `severity` is at or above `threshold`.

    A threshold of "none" means nothing meets it, so no finding can fail a run.
    """
    if threshold == "none":
        return False
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)

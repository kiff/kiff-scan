"""FIXTURE -- scanner input, never imported.

Every tool is governed by a single module-level hook installed over the agent,
so findings here must be cleared with `module_hook` evidence -- the coarse-but-
real signal, distinguishable in the report from a per-call proof.
"""

import boto3


def tool(fn):
    return fn


class KiffGuard:
    def __init__(self, tenant: str, mode: str = "enforce"):
        self.tenant = tenant
        self.mode = mode


class Agent:
    def __init__(self, tools, tool_hooks):
        self.tools = tools
        self.tool_hooks = tool_hooks


@tool
def drop_database(database_id: str):
    """Delete a database instance."""
    rds = boto3.client("rds")
    return rds.delete_db_instance(DBInstanceIdentifier=database_id)


@tool
def issue_refund(order_id: str, amount_cents: int):
    """Refund an order."""
    import stripe

    return stripe.Refund.create(charge=order_id, amount=amount_cents)


# One hook governs every tool on this agent.
agent = Agent(
    tools=[drop_database, issue_refund],
    tool_hooks=[KiffGuard(tenant="acme", mode="enforce")],
)

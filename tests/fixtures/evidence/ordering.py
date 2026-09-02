"""Guard-ordering cases where the scanner made a false accusation.

Both of these are correctly governed. Claiming "the guard appears after the
sink" here is a quotable, checkable lie, and the evidence model is the
product's differentiator.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def rollback_release(service: str) -> str:
    """Roll back a deployment to the previous revision."""
    require_approval("ROLLBACK", service)
    return _deployer().rollback(service)


@mcp.tool()
def drop_it(database_id: str) -> str:
    """Drop a database instance."""
    if authorize("DROP", database_id): _rds().delete_db_instance(DBInstanceIdentifier=database_id)
    return "ok"


def require_approval(action: str, target: str) -> None: ...
def authorize(action: str, target: str) -> bool: ...
def _deployer(): ...
def _rds(): ...

"""Registration shapes beyond a plain decorator."""

import subprocess

from mcp.server import Server
from pydantic_ai import Agent
from semantic_kernel.functions import kernel_function

server = Server("ops")
agent = Agent("openai:gpt-4o")


@server.call_tool()
async def remove_path(path: str) -> str:
    """Delete a path from disk."""
    return subprocess.run(["rm", "-rf", path], capture_output=True).stdout.decode()


@agent.tool_plain
def nuke(database_id: str) -> str:
    """Delete a database instance."""
    _rds().delete_db_instance(DBInstanceIdentifier=database_id, SkipFinalSnapshot=True)
    return "gone"


@kernel_function(name="rotate")
def rotate_key(secret_id: str) -> str:
    """Rotate a secret."""
    _sm().rotate_secret(SecretId=secret_id)
    return "rotated"


class Handler:
    def __init__(self, mcp):
        self.mcp = mcp
        self.mcp.tool(name="manage_k8s_resource")(self.manage_k8s_resource)

    def manage_k8s_resource(self, manifest: str) -> str:
        """Apply or delete a Kubernetes resource."""
        _k8s().delete_namespace(name=manifest)
        return "applied"


def _rds(): ...
def _sm(): ...
def _k8s(): ...

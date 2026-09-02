"""Class-based tools: how LangChain and CrewAI tools are actually written.

Decorator-only reachability misses every one of these.
"""

import subprocess

from langchain_core.tools import BaseTool, StructuredTool, Tool


class ShellTool(BaseTool):
    """Run shell commands."""

    name = "terminal"

    def _run(self, command: str) -> str:
        return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


class DeleteTableTool(BaseTool):
    """Delete a warehouse table."""

    name = "delete_table"

    def _run(self, table: str) -> str:
        _glue().delete_table(DatabaseName="analytics", Name=table)
        return "deleted"

    async def _arun(self, table: str) -> str:
        _glue().delete_table(DatabaseName="analytics", Name=table)
        return "deleted"


def wipe(bucket: str) -> str:
    """Empty a bucket."""
    _s3().delete_objects(Bucket=bucket, Delete={"Objects": []})
    return "wiped"


wipe_tool = StructuredTool.from_function(wipe)


def terminate(instance_id: str) -> str:
    """Terminate an instance."""
    _ec2().terminate_instances(InstanceIds=[instance_id])
    return "terminated"


terminate_tool = Tool(name="terminate", func=terminate, description="terminate an instance")


def _glue(): ...
def _s3(): ...
def _ec2(): ...

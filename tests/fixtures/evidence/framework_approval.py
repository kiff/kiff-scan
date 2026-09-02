"""Framework-native human-in-the-loop metadata.

Every one of these declares a confirmation or approval boundary in the way its
own framework provides. Reporting them as ungoverned is the single most
embarrassing miss in the audit corpus: agno's examples live in a folder
literally named human_in_the_loop.
"""

from agno.tools import tool
from agents import function_tool


@tool(requires_confirmation=True)
def delete_bucket(bucket: str) -> str:
    """Delete an S3 bucket."""
    _s3().delete_bucket(Bucket=bucket)
    return "deleted"


@tool(requires_user_input=True)
def rotate_secret(secret_id: str) -> str:
    """Rotate a secret."""
    _sm().rotate_secret(SecretId=secret_id)
    return "rotated"


@function_tool(needs_approval=True)
def terminate_instance(instance_id: str) -> str:
    """Terminate an EC2 instance."""
    _ec2().terminate_instances(InstanceIds=[instance_id])
    return "terminated"


def _s3(): ...
def _sm(): ...
def _ec2(): ...

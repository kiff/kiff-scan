"""FIXTURE -- scanner input, never imported.

The regression fixture for the per-file governance bug. This module contains a
properly governed tool AND an unguarded one, plus two partial cases. A scanner
that judges governance per *file* reports every tool here as governed and misses
the real exposure. Each function documents the verdict it must receive.
"""

import boto3


def tool(fn):
    return fn


def authorize(action, subject):
    """Stand-in for a codebase's own authorization check."""
    return True


def decide(action, entity, params):
    """Stand-in for a state-aware decision boundary."""
    return {"outcome": "allowed"}


@tool
def drop_replica(database_id: str):
    """GOVERNED: decision precedes the sink."""
    decision = decide("DROP_DATABASE", database_id, {})
    if decision["outcome"] != "allowed":
        raise PermissionError(decision)
    rds = boto3.client("rds")
    return rds.delete_db_instance(DBInstanceIdentifier=database_id)


@tool
def drop_production(database_id: str):
    """UNGOVERNED: no check at all. Must be reported even though its neighbour
    in this same file is governed."""
    rds = boto3.client("rds")
    return rds.delete_db_instance(DBInstanceIdentifier=database_id)


@tool
def delete_backups(bucket: str):
    """UNGOVERNED: the check runs AFTER the destructive call, so it cannot have
    gated it. Must be reported, with evidence naming the ordering."""
    s3 = boto3.client("s3")
    result = s3.delete_objects(Bucket=bucket, Delete={})
    authorize("DELETE_BACKUPS", bucket)
    return result


@tool
def terminate_node(instance_id: str):
    """UNGOVERNED: the word 'authorize' appears only in a comment and a string,
    which a text-matching scanner would wrongly credit as a guard.

    # authorize this later
    """
    note = "remember to authorize() this path"
    ec2 = boto3.client("ec2")
    return ec2.terminate_instances(InstanceIds=[instance_id], DryRun=False)


@requires_approval  # noqa: F821 - fixture: decorator resolved by the scanner, not at runtime
@tool
def scale_cluster(cluster: str, size: int):
    """GOVERNED: a recognised guard decorator wraps the function."""
    return subprocess_run(["kubectl", "scale", f"deploy/{cluster}"])  # noqa: F821

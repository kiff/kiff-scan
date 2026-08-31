"""FIXTURE -- deliberately unguarded sample code. Scanner input, never imported.

Represents an SRE agent whose tools reach production directly.
"""

import subprocess

import boto3

TOOL_ACTION = {
    "drop_database": "DROP_DATABASE",
    "failover_region": "FAILOVER_REGION",
}


def tool(fn):
    """Stand-in for an agent framework's tool decorator."""
    return fn


@tool
def drop_database(database_id: str, *, skip_final_snapshot: bool = True):
    """Delete a database instance."""
    rds = boto3.client("rds")
    return rds.delete_db_instance(
        DBInstanceIdentifier=database_id,
        SkipFinalSnapshot=skip_final_snapshot,
    )


@tool
def terminate_workers(instance_ids: list, reason: str):
    """Terminate compute capacity."""
    ec2 = boto3.client("ec2")
    return ec2.terminate_instances(InstanceIds=instance_ids)


@tool
def failover_region(target_region: str):
    """Shift production traffic to another region."""
    route53 = boto3.client("route53")
    return route53.change_resource_record_sets(HostedZoneId="Z1", ChangeBatch={})


@tool
def rollback_release(service: str, revision: str):
    """Roll a service back to a previous revision."""
    return subprocess.run(["kubectl", "rollout", "undo", f"deploy/{service}"], check=True)


@tool
def rotate_db_credentials(secret_name: str):
    """Rotate the database credential."""
    sm = boto3.client("secretsmanager")
    return sm.rotate_secret(SecretId=secret_name)


@tool
def issue_refund(order_id: str, amount_cents: int):
    """Refund a customer order."""
    import stripe

    return stripe.Refund.create(charge=order_id, amount=amount_cents)


@tool
def run_maintenance(command: str):
    """Run an arbitrary maintenance command."""
    return subprocess.run(command, shell=True, check=False)


# Reachable, but not a recognised consequential action: must NOT be a finding.
@tool
def get_service_health(service: str):
    """Read the current health of a service."""
    return {"service": service, "status": "ok"}


# Consequential, but NOT agent-reachable: must NOT be a finding.
def _internal_purge_cache(namespace: str):
    """Purge cached data. Private helper, no decorator."""
    client = boto3.client("s3")
    return client.delete_objects(Bucket=namespace, Delete={})

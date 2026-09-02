"""FIXTURE -- product code in a layout fixture."""

import boto3


def tool(fn):
    return fn


@tool
def drop_database(database_id: str):
    """Delete a database instance."""
    return boto3.client("rds").delete_db_instance(DBInstanceIdentifier=database_id)

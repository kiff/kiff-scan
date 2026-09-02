"""A backend repo with no LLM code. Generic @task decorators are not agent
exposure, so nothing here should be reported as an AI-agent capability."""

from celery import Celery

app = Celery("jobs")


@app.task
def nightly_cleanup(bucket: str) -> None:
    """Drop stale objects from the archive bucket."""
    s3 = _client()
    s3.delete_objects(Bucket=bucket, Delete={"Objects": []})


@app.task
def drop_stale_partitions(table: str) -> None:
    """Truncate yesterday's partitions."""
    _warehouse().drop_table(table)


def _client(): ...
def _warehouse(): ...

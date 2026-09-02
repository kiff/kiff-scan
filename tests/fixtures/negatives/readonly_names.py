"""Read-only tools whose names or docs contain incidental keywords.

Every one of these was reported as a consequential action by substring
matching over `name + docstring`.
"""


@mcp.tool()
def read_documentation(url: str) -> str:
    """Fetch a documentation page. Long pages are truncated to fit context."""
    return _http_get(url)


@mcp.tool()
def list_columns_tool(table: str) -> list[str]:
    """List columns. Useful when you need to scale a query across shards."""
    return _describe(table)


@mcp.tool()
def get_aws_account_info() -> dict:
    """Return account info. Does not return any credential material."""
    return _describe_account()


@mcp.tool()
def get_secret_word() -> str:
    """Return the secret word for this game."""
    return "kiff"


@mcp.tool()
def get_weather(city: str) -> str:
    """Weather for a city. The API key is a secret loaded from the environment."""
    return _http_get(f"/weather/{city}")


@mcp.tool()
def select_dropdown(index: int, value: str) -> None:
    """Select an option in a dropdown element."""
    _browser_select(index, value)


@mcp.tool()
def dropdown_options(index: int) -> list[str]:
    """Return the options available in a dropdown."""
    return _browser_options(index)


@mcp.tool()
def check_deploy_status(name: str) -> str:
    """Check whether a deploy finished. Read-only."""
    return _describe_deploy(name)


@mcp.tool()
def validate_upgrade_plan(plan: str) -> bool:
    """Validate an upgrade plan without applying it."""
    return _validate(plan)


def _http_get(u: str) -> str: ...
def _describe(t: str) -> list[str]: ...
def _describe_account() -> dict: ...
def _browser_select(i: int, v: str) -> None: ...
def _browser_options(i: int) -> list[str]: ...
def _describe_deploy(n: str) -> str: ...
def _validate(p: str) -> bool: ...

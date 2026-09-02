"""Innocent agent code. Nothing here is a consequential action.

Regression for the audit's most quotable false positives: `agent.run()` is
the most common method name in every agent framework, and `Console.capture()`
is rich's output helper. Neither is shell execution or money movement.
"""

from rich.console import Console

agent = object()


@agent.tool
def ask_specialist(question: str) -> str:
    """Delegate to a sub-agent and return its answer."""
    return agent.run(question)


@agent.tool
async def ask_specialist_async(question: str) -> str:
    """Delegate asynchronously."""
    return await agent.run(question)


@agent.tool
def render_panel(text: str) -> str:
    """Render text through rich, capturing the output."""
    console = Console()
    with console.capture() as capture:
        console.print(text)
    return capture.get()


@agent.tool
def call_helper(payload: dict) -> dict:
    """A bare .call() on an arbitrary object is not execution."""
    client = object()
    return client.call(payload)

"""Command-line interface for Airlock."""

from __future__ import annotations

import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .brief import render_brief
from .extractor import MockAdapter, OllamaAdapter
from .ingest import load_messages
from .pipeline import process_messages
from .signals import SignalConfig
from .store import Store

app = typer.Typer(help="Airlock: a local, prompt-injection-resistant overnight inbox brief.")
console = Console()

DB_OPTION = typer.Option("airlock.db", help="Path to the local SQLite store.")


def _adapter(model: str):
    if model == "mock":
        return MockAdapter()
    return OllamaAdapter(model=model)


@app.command()
def ingest(
    path: str = typer.Argument(..., help="Path to a .mbox, .eml, or WhatsApp .txt export."),
    db: str = DB_OPTION,
) -> None:
    """Load messages into the local staging store."""
    store = Store(db)
    try:
        messages = load_messages(path)
        store.stage_messages(messages)
        console.print(f"Staged [bold]{len(messages)}[/bold] messages into [bold]{db}[/bold].")
    finally:
        store.close()


@app.command()
def run(
    model: str = typer.Option("gemma3:4b", help="Ollama model tag, or 'mock' for the offline adapter."),
    limit: int | None = typer.Option(None, help="Process at most this many staged messages."),
    db: str = DB_OPTION,
) -> None:
    """Process staged messages through the quarantine pipeline."""
    store = Store(db)
    try:
        messages = store.staged_messages(limit=limit)
        if not messages:
            console.print("No staged messages. Run 'airlock ingest <path>' first.")
            raise typer.Exit(code=1)
        records = process_messages(messages, _adapter(model), SignalConfig.empty(), store)

        counts: dict[str, int] = {}
        for record in records:
            section = "review" if record.unparsed else _section_of(store, record.message_id)
            counts[section] = counts.get(section, 0) + 1

        table = Table(title=f"Processed {len(records)} messages")
        table.add_column("Section")
        table.add_column("Count")
        for section in ("needs_you", "deadlines_amounts", "review", "fyi"):
            if counts.get(section):
                table.add_row(section, str(counts[section]))
        console.print(table)
    finally:
        store.close()


def _section_of(store: Store, message_id: str) -> str:
    row = store.get_brief_data(message_id)
    return row["section"] if row else "fyi"


@app.command()
def brief(
    open_browser: bool = typer.Option(False, "--open", help="Open the generated brief in a browser."),
    output: str = typer.Option("brief.html", help="Output path for the HTML brief."),
    db: str = DB_OPTION,
) -> None:
    """Render the local HTML brief."""
    store = Store(db)
    try:
        path = render_brief(store, output)
        console.print(f"Wrote brief to [bold]{path}[/bold].")
        if open_browser:
            webbrowser.open(path.resolve().as_uri())
    finally:
        store.close()


@app.command()
def proposals(db: str = DB_OPTION) -> None:
    """List pending action proposals."""
    store = Store(db)
    try:
        rows = store.list_proposals()
        if not rows:
            console.print("No proposals.")
            return
        table = Table(title="Proposals")
        table.add_column("ID")
        table.add_column("Message")
        table.add_column("Kind")
        table.add_column("Status")
        for row in rows:
            table.add_row(str(row["id"]), row["message_id"], row["kind"], row["status"])
        console.print(table)
    finally:
        store.close()


@app.command()
def approve(proposal_id: int = typer.Argument(..., help="Proposal id to approve."), db: str = DB_OPTION) -> None:
    """Approve a pending proposal with a human approval token."""
    store = Store(db)
    try:
        if store.approve_proposal(proposal_id):
            console.print(f"Approved proposal [bold]{proposal_id}[/bold].")
        else:
            console.print(f"Proposal [bold]{proposal_id}[/bold] not found or already approved.")
            raise typer.Exit(code=1)
    finally:
        store.close()


@app.command()
def serve_mcp(db: str = DB_OPTION) -> None:
    """Run the read-only MCP server over stdio."""
    from .mcp_server import serve

    serve(db)


@app.command()
def demo(
    model: str = typer.Option("mock", help="Ollama model tag, or 'mock' for the offline adapter."),
    db: str = DB_OPTION,
) -> None:
    """Run a self-contained demonstration on a synthetic poisoned inbox."""
    from .demo import run_demo

    run_demo(model=model, db=db)


@app.command()
def eval(
    quarantine_model: str = typer.Option("gemma3:4b", help="Model used by the quarantine extractor."),
    agent_model: str = typer.Option("gemma3:4b", help="Model used by the agent systems."),
    policy: str = typer.Option("ollama", help="Agent policy: ollama, gullible, or null."),
    limit: int | None = typer.Option(None, help="Cap the number of attacks (smoke run)."),
    skip: str = typer.Option("", help="Comma-separated stages to skip."),
) -> None:
    """Run the full evaluation harness and regenerate the report."""
    from eval.run_all import run_all

    skip_stages = tuple(stage.strip() for stage in skip.split(",") if stage.strip())
    result = run_all(
        quarantine_model=quarantine_model,
        agent_model=agent_model,
        agent_policy=policy,
        limit=limit,
        skip=skip_stages,
    )
    console.print(f"Ran: {', '.join(result['ran'])}")
    console.print(f"Report: [bold]{result['report']}[/bold]")


if __name__ == "__main__":
    app()

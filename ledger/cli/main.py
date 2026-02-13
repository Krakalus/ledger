# ledger/cli/main.py
"""
CLI for inspecting, verifying and exporting tamper-evident AI conversation logs.
"""

import os
import json
import sqlite3
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ledger.storage import SQLiteStorage
from ledger.verify.verifier import LogVerifier

app = typer.Typer(
    name="attested-logs",
    help="Inspect, verify and export tamper-evident AI conversation logs",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def get_db_path(db_flag: Optional[Path] = None) -> Path:
    """Resolve DB path in this order:
    1. --db flag
    2. LEDGER_DB_PATH environment variable
    3. Default: ~/.ledger/blackbox-logs.db
    """
    if db_flag:
        path = db_flag.resolve()
    else:
        env_path = os.environ.get("LEDGER_DB_PATH")
        if env_path:
            path = Path(env_path).resolve()
        else:
            path = Path.home() / ".ledger" / "blackbox-logs.db"

    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@app.callback()
def main(
    db: Optional[Path] = typer.Option(
        None,
        "--db",
        help="Path to SQLite database (overrides LEDGER_DB_PATH env var)",
    ),
):
    """Manage attested AI conversation logs."""
    pass


@app.command()
def sessions(
    db: Optional[Path] = typer.Option(None, "--db", hidden=True),
):
    """List all recorded sessions with message counts and last activity."""
    db_path = get_db_path(db)

    if not db_path.exists():
        console.print(f"[red]Database file not found: {db_path}[/]")
        console.print("[yellow]To get started:[/]")
        console.print("  • Run an agent session or demo first (creates/populates DB)")
        console.print("  • Set env var: export LEDGER_DB_PATH=/path/to/your.db")
        console.print("  • Or use --db: attested-logs sessions --db /custom/path.db")
        raise typer.Exit(1)

    try:
        storage = SQLiteStorage(db_path)
    except Exception as e:
        console.print(f"[red]Failed to open database: {str(e)}[/]")
        console.print("[yellow]The file may be corrupted or not a valid SQLite DB.[/]")
        raise typer.Exit(1)

    try:
        session_list = storage.list_sessions()
    except sqlite3.OperationalError as e:
        console.print(f"[yellow]Database is empty or schema missing: {str(e)}[/]")
        console.print("  Run an agent session first to create the table and log messages.")
        raise typer.Exit(0)

    if not session_list:
        console.print("[yellow]No sessions found in database.[/]")
        console.print("  (DB exists but no logged messages yet)")
        return

    table = Table(title="Recorded Sessions")
    table.add_column("Session ID")
    table.add_column("Messages")
    table.add_column("Last Activity")

    for sid in session_list:
        count = storage.get_message_count(sid)
        last_ts = storage.get_latest_timestamp(sid) or "—"
        table.add_row(sid, str(count), last_ts)

    console.print(table)


@app.command()
def messages(
    session_id: str = typer.Argument(..., help="Session ID to display"),
    db: Optional[Path] = typer.Option(None, "--db", hidden=True),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of recent messages to show"),
):
    """Show the most recent messages in a given session."""
    db_path = get_db_path(db)

    if not db_path.exists():
        console.print(f"[red]Database file not found: {db_path}[/]")
        raise typer.Exit(1)

    try:
        storage = SQLiteStorage(db_path)
    except Exception as e:
        console.print(f"[red]Failed to open database: {str(e)}[/]")
        raise typer.Exit(1)

    try:
        msgs = storage.query_messages(session_id, limit=limit)
    except sqlite3.OperationalError as e:
        console.print(f"[yellow]Database is empty or schema missing: {str(e)}[/]")
        console.print("  Run an agent session to create the table and log messages.")
        raise typer.Exit(0)

    if not msgs:
        console.print(f"[yellow]No messages found for session '{session_id}'[/]")
        return

    for msg in msgs:
        console.print(f"[bold cyan]{msg.sequence:4d} | {msg.timestamp} | {msg.agent_role.upper():10} | {msg.agent_id}[/]")
        console.print(f"  {msg.content[:160]}{'...' if len(msg.content) > 160 else ''}")
        console.print("  " + "─" * 90)


@app.command()
def verify(
    session_id: str = typer.Argument(..., help="Session ID to verify"),
    db: Optional[Path] = typer.Option(None, "--db", hidden=True),
):
    """Verify the integrity of a session (hash chain + signatures)."""
    db_path = get_db_path(db)

    if not db_path.exists():
        console.print(f"[red]Database file not found: {db_path}[/]")
        raise typer.Exit(1)

    try:
        storage = SQLiteStorage(db_path)
    except Exception as e:
        console.print(f"[red]Failed to open database: {str(e)}[/]")
        raise typer.Exit(1)

    trusted_keys = {}

    if not trusted_keys:
        console.print("[yellow]Warning: No trusted public keys loaded — signature checks skipped.[/]")
        console.print("  Add trusted keys via config/env for full verification.")

    verifier = LogVerifier(trusted_keys=trusted_keys)

    try:
        result = verifier.verify_from_storage(session_id, storage)
    except Exception as e:
        console.print(f"[red]Verification failed: {str(e)}[/]")
        raise typer.Exit(1)

    if result.is_valid:
        console.print(f"[green]✓ Session '{session_id}' is valid[/]")
        console.print(f"  {result.message}")
    else:
        console.print(f"[red]✗ Verification failed for session '{session_id}'[/]")
        for failure in result.failures:
            console.print(f"  • [{failure.index}] {failure.category}: {failure.message}")


@app.command()
def export(
    session_id: str = typer.Argument(..., help="Session ID to export"),
    db: Optional[Path] = typer.Option(None, "--db", hidden=True),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file (default: <session_id>.jsonl)"),
):
    """Export a session as JSONL (one signed message per line)."""
    db_path = get_db_path(db)

    if not db_path.exists():
        console.print(f"[red]Database file not found: {db_path}[/]")
        raise typer.Exit(1)

    try:
        storage = SQLiteStorage(db_path)
    except Exception as e:
        console.print(f"[red]Failed to open database: {str(e)}[/]")
        raise typer.Exit(1)

    try:
        msgs = storage.load_messages(session_id)
    except Exception as e:
        console.print(f"[red]Failed to load session '{session_id}': {str(e)}[/]")
        raise typer.Exit(1)

    if not msgs:
        console.print(f"[yellow]No messages found for session '{session_id}'[/]")
        raise typer.Exit(0)

    out_path = output or Path(f"{session_id}.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for msg in msgs:
            # Export full message as JSON (including proof)
            json.dump(msg.to_dict(), f, separators=(",", ":"))
            f.write("\n")

    console.print(f"[green]Exported {len(msgs)} messages to {out_path}[/]")
    console.print("Format: JSONL — one signed message per line")


if __name__ == "__main__":
    app()
"""Manual notes workspace commands."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from pentnote.workspace.store import (
    active_workspace,
    append_to_host_note,
    append_to_note_path,
    finding_note_path,
    note_id,
    now_iso,
    target_type,
)

console = Console()


@click.group()
def note() -> None:
    """Manual notes workspace."""


@note.command()
@click.argument("target")
@click.argument("text")
@click.option("--tag", "tags", multiple=True)
def add(target: str, text: str, tags: tuple[str, ...]) -> None:
    """Add a manual note."""

    engagement, store = active_workspace()
    kind = target_type(target)
    item = {
        "id": note_id(),
        "target": target,
        "target_type": kind,
        "finding": None if kind == "host" else target,
        "content": text,
        "date": now_iso(),
        "tags": list(tags),
    }
    store.add_note(item)
    if kind == "host":
        append_to_host_note(engagement.notes_dir, target, text)
    else:
        note_path = finding_note_path(engagement.notes_dir, target)
        if note_path is not None:
            append_to_note_path(note_path, text)
    console.print(f"[✓] Note added to {target}")


@note.command("list")
@click.option("--host")
@click.option("--tag")
@click.option("--finding")
def list_notes(host: str | None, tag: str | None, finding: str | None) -> None:
    """Show notes."""

    _, store = active_workspace()
    notes = store.get_notes({"host": host, "tag": tag, "finding": finding})
    if not notes:
        console.print("No notes found.")
        return
    table = Table(title="Notes", show_lines=True)
    for column in ("#", "Date", "Target", "Content", "Tags"):
        table.add_column(column)
    for index, item in enumerate(notes, 1):
        table.add_row(
            str(index),
            item.get("date", ""),
            item.get("target", ""),
            item.get("content", ""),
            ", ".join(item.get("tags", [])),
        )
    console.print(table)


@note.command("delete")
@click.argument("number", type=int)
@click.option("--host")
@click.option("--tag")
@click.option("--finding")
def delete_note(
    number: int,
    host: str | None,
    tag: str | None,
    finding: str | None,
) -> None:
    """Delete a note by the number shown in note list."""

    _, store = active_workspace()
    notes = store.get_notes({"host": host, "tag": tag, "finding": finding})
    if number < 1 or number > len(notes):
        raise click.ClickException(f"No note #{number} found.")
    deleted = store.delete_note(notes[number - 1]["id"])
    if deleted is None:
        raise click.ClickException(f"No note #{number} found.")
    console.print(f"[✓] Deleted note #{number}: {deleted.get('content', '')}")

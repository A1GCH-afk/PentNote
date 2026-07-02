"""Loot tracker workspace commands."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pentnote.core.engagement import EngagementError, load_engagement
from pentnote.evidence.screenshot import capture_and_link_screenshot
from pentnote.workspace.log import add_log
from pentnote.workspace.store import active_workspace, now_iso, write_loot_markdown

console = Console()

ICONS = {
    "flag": "🚩",
    "shell": "💻",
    "file": "📄",
    "hash": "🔑",
    "key": "🗝️",
    "secret": "🔒",
}


@click.group()
def loot() -> None:
    """Loot tracker."""


@loot.command()
@click.option(
    "--type",
    "loot_type",
    required=True,
    type=click.Choice(["file", "flag", "shell", "hash", "secret", "key"]),
)
@click.option("--host", required=True)
@click.option("--path")
@click.option("--value")
@click.option("--user")
@click.option("--method")
@click.option("--notes", default="")
def add(
    loot_type: str,
    host: str,
    path: str | None,
    value: str | None,
    user: str | None,
    method: str | None,
    notes: str,
) -> None:
    """Add loot."""

    engagement, store = active_workspace()
    item_value = _value_for_loot(loot_type, path, value, user, method)
    item = {
        "type": loot_type,
        "value": item_value,
        "host": host,
        "user": user,
        "date": now_iso(),
        "notes": notes or method or "",
    }
    store.add_loot(item)
    write_loot_markdown(engagement.notes_dir, store.get_loot({}))
    if loot_type == "flag":
        add_log(f"Flag captured on {host}", host, ("loot", "flag"))
    console.print(f"[✓] Loot added: {loot_type} on {host}")


@loot.command("list")
@click.option("--host")
@click.option("--type", "loot_type")
def list_loot(host: str | None, loot_type: str | None) -> None:
    """Show loot."""

    _, store = active_workspace()
    items = store.get_loot({"host": host, "type": loot_type})
    if not items:
        console.print("No loot found.")
        return
    table = Table(title="Loot")
    for column in ("#", "Type", "Host", "Value/Path", "User", "Date"):
        table.add_column(column)
    for index, item in enumerate(items, 1):
        style = _style(item.get("type", ""))
        loot_label = f"{ICONS.get(item.get('type', ''), '')}{item.get('type', '')}"
        table.add_row(
            str(index),
            f"[{style}]{loot_label}[/{style}]" if style else loot_label,
            item.get("host", ""),
            item.get("value", ""),
            item.get("user") or "",
            item.get("date", ""),
        )
    console.print(table)


@loot.command()
def summary() -> None:
    """Show loot summary."""

    _, store = active_workspace()
    counts = Counter(item.get("type") for item in store.get_loot({}))
    console.print(
        Panel(
            "\n".join(
                [
                    f"Shells obtained:  {counts['shell']}",
                    f"Flags captured:   {counts['flag']}",
                    f"Files accessed:   {counts['file']}",
                    f"Hashes collected: {counts['hash']}",
                    f"SSH keys found:   {counts['key']}",
                ]
            ),
            title="Loot Summary",
        )
    )


@loot.command("snap")
@click.argument("target_ip")
@click.option("--vault", "vault_path", type=click.Path(path_type=Path))
def loot_snap(target_ip: str, vault_path: Path | None) -> None:
    """Capture a screenshot and link it to a target note."""

    try:
        engagement = load_engagement(vault_path)
    except EngagementError as exc:
        raise click.ClickException(str(exc)) from exc
    try:
        result = capture_and_link_screenshot(engagement, target_ip)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"[✓] wrote: {result.attachment_path}")
    console.print(f"[✓] linked: {result.note_path}")


def _value_for_loot(
    loot_type: str,
    path: str | None,
    value: str | None,
    user: str | None,
    method: str | None,
) -> str:
    if loot_type in {"file", "key"}:
        if not path:
            raise click.ClickException(f"--path is required for loot type {loot_type}")
        return path
    if loot_type == "shell":
        if not user:
            raise click.ClickException("--user is required for shell loot")
        return method or user
    if loot_type in {"flag", "hash", "secret"}:
        if not value:
            raise click.ClickException(f"--value is required for loot type {loot_type}")
        if loot_type in {"hash", "secret"} and not user:
            raise click.ClickException(f"--user is required for loot type {loot_type}")
        return value
    raise click.ClickException(f"Unknown loot type: {loot_type}")


def _style(loot_type: str) -> str:
    return {
        "flag": "bright_green bold",
        "shell": "bright_red bold",
        "file": "white",
        "hash": "yellow",
        "key": "cyan",
        "secret": "magenta",
    }.get(loot_type, "")

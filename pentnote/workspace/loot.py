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

# Number of leading uuid4 characters shown as an entry's public id. `loot list`
# displays this prefix and `loot remove <id>` resolves an entry by it, so the
# operator never has to type a full 36-char uuid.
SHORT_ID_LEN = 8

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
@click.option("--user")
def list_loot(host: str | None, loot_type: str | None, user: str | None) -> None:
    """Show loot."""

    _, store = active_workspace()
    items = store.get_loot({"host": host, "type": loot_type, "user": user})
    if not items:
        console.print("No loot found.")
        return
    table = Table(title="Loot")
    for column in ("#", "ID", "Type", "Host", "Value/Path", "User", "Date"):
        table.add_column(column)
    for index, item in enumerate(items, 1):
        style = _style(item.get("type", ""))
        loot_label = f"{ICONS.get(item.get('type', ''), '')}{item.get('type', '')}"
        table.add_row(
            str(index),
            _short_id(item),
            f"[{style}]{loot_label}[/{style}]" if style else loot_label,
            item.get("host", ""),
            item.get("value", ""),
            item.get("user") or "",
            item.get("date", ""),
        )
    console.print(table)


@loot.command("remove")
@click.argument("loot_id", required=False)
@click.option(
    "--last", "remove_last", is_flag=True, help="Remove the most recently added entry."
)
@click.option("-y", "--yes", "assume_yes", is_flag=True, help="Skip confirmation.")
def remove_loot(loot_id: str | None, remove_last: bool, assume_yes: bool) -> None:
    """Remove a loot entry by ID (or --last)."""

    engagement, store = active_workspace()
    items = store.get_loot({})
    if not items:
        raise click.ClickException("No loot to remove.")
    if remove_last and loot_id:
        raise click.ClickException("Give either an <id> or --last, not both.")
    if remove_last:
        target = items[-1]
    elif loot_id:
        target = _resolve_loot(items, loot_id)
    else:
        raise click.ClickException("Give a loot <id> to remove, or use --last.")

    label = _loot_label(target)
    if not assume_yes and not click.confirm(f"Remove loot: {label}?"):
        console.print("Aborted.")
        return
    store.delete_loot(str(target.get("id", "")))
    write_loot_markdown(engagement.notes_dir, store.get_loot({}))
    console.print(f"[✓] Loot removed: {label}")


@loot.command()
@click.option("--host")
@click.option("--type", "loot_type")
@click.option("--user")
def summary(host: str | None, loot_type: str | None, user: str | None) -> None:
    """Show loot summary."""

    _, store = active_workspace()
    counts = Counter(
        item.get("type")
        for item in store.get_loot({"host": host, "type": loot_type, "user": user})
    )
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


def _short_id(item: dict[str, str]) -> str:
    return str(item.get("id", ""))[:SHORT_ID_LEN]


def _resolve_loot(items: list[dict], loot_id: str) -> dict:
    """Resolve a loot entry from its full id or a unique short-id prefix."""

    matches = [
        item
        for item in items
        if str(item.get("id", "")) == loot_id
        or str(item.get("id", "")).startswith(loot_id)
    ]
    if not matches:
        raise click.ClickException(f"No loot entry with id {loot_id!r}.")
    if len(matches) > 1:
        raise click.ClickException(
            f"Loot id {loot_id!r} is ambiguous ({len(matches)} matches); "
            "use more characters."
        )
    return matches[0]


def _loot_label(item: dict) -> str:
    """Human-readable descriptor for confirmation and result messages."""

    label = f"{item.get('type', '')} on {item.get('host', '')}"
    if item.get("user"):
        label += f" (user {item['user']})"
    return f"{label} [{_short_id(item)}]"


def _style(loot_type: str) -> str:
    return {
        "flag": "bright_green bold",
        "shell": "bright_red bold",
        "file": "white",
        "hash": "yellow",
        "key": "cyan",
        "secret": "magenta",
    }.get(loot_type, "")

"""Attack log workspace commands."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from pentnote.ghostlog.daemon import (
    run_history_daemon,
    start_daemon,
    status_daemon,
    stop_daemon,
)
from pentnote.models import WorkspaceLog
from pentnote.workspace.store import (
    WorkspaceStore,
    active_workspace,
    append_timeline_entry,
    now_iso,
)

console = Console()


class LogGroup(click.Group):
    """Group that treats non-command arguments as a log message."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if (
            args
            and args[0] not in self.commands
            and args[0] not in {"-h", "--help"}
            and not args[0].startswith("-")
        ):
            ctx.args = args
            return []
        return super().parse_args(ctx, args)


@click.group(
    cls=LogGroup,
    invoke_without_command=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.option("--start", is_flag=True, help="Start Ghost Log lifecycle state.")
@click.option("--stop", is_flag=True, help="Stop Ghost Log lifecycle state.")
@click.option("--status", "show_status", is_flag=True, help="Show Ghost Log state.")
@click.option("--daemon", is_flag=True, help="Run Ghost Log shell-history daemon.")
@click.option("--history", "history_path", type=click.Path(path_type=Path))
@click.option("--model", help="Local Ollama model for Ghost Log extraction.")
@click.option("--quiet", is_flag=True, help="Suppress Ghost Log extraction feedback.")
@click.option(
    "--finding", "finding_query", help="Show Ghost Log entries for a finding."
)
@click.option("--review", is_flag=True, help="Show Ghost Log pending review queue.")
@click.option(
    "--timeline",
    "show_timeline",
    is_flag=True,
    help="Rebuild the engagement timeline instead of logging a message.",
)
@click.option(
    "--vault",
    "vault_path",
    type=click.Path(path_type=Path),
    help="Vault path (used with --timeline).",
)
@click.pass_context
def log(
    ctx: click.Context,
    start: bool = False,
    stop: bool = False,
    show_status: bool = False,
    daemon: bool = False,
    history_path: Path | None = None,
    model: str | None = None,
    quiet: bool = False,
    finding_query: str | None = None,
    review: bool = False,
    show_timeline: bool = False,
    vault_path: Path | None = None,
) -> None:
    """Attack log."""

    if ctx.invoked_subcommand is not None:
        return
    if show_timeline:
        from pentnote.core.engagement import (
            EngagementError,
            load_engagement,
            load_findings,
        )
        from pentnote.generators.timeline import write_timeline

        try:
            engagement = load_engagement(vault_path)
        except EngagementError as exc:
            raise click.ClickException(str(exc)) from exc
        path = write_timeline(
            load_findings(engagement),
            engagement.notes_dir,
            engagement_name=engagement.name,
        )
        click.echo(f"wrote: {path}")
        return
    if sum([start, stop, show_status, daemon, bool(review)]) > 1:
        raise click.ClickException("Use only one lifecycle option at a time.")
    if start:
        engagement, _ = active_workspace()
        path = start_daemon(engagement)
        console.print(f"[✓] Ghost Log started: {path}")
        return
    if stop:
        engagement, _ = active_workspace()
        path = stop_daemon(engagement)
        console.print(f"[✓] Ghost Log stopped: {path}")
        _print_session_summary(status_daemon(engagement))
        return
    if show_status:
        engagement, store = active_workspace()
        _print_status(status_daemon(engagement), store)
        return
    if review:
        _, store = active_workspace()
        _print_review_queue(store)
        return
    if daemon:
        engagement, _ = active_workspace()
        console.print(
            "[*] Ghost Log daemon watching shell history. Press Ctrl+C to stop."
        )
        try:
            result = asyncio.run(
                run_history_daemon(
                    engagement,
                    history_path=history_path,
                    model=model,
                    quiet=quiet,
                )
            )
        except KeyboardInterrupt:
            console.print("[✓] Ghost Log stopped.")
            return
        console.print(
            "[✓] Ghost Log stopped: "
            f"processed={result.processed} ignored={result.ignored} "
            f"credentials={result.extracted_credentials} "
            f"findings={result.extracted_findings} "
            f"log_entries={result.extracted_log_entries}"
        )
        return
    if finding_query:
        _, store = active_workspace()
        entries = find_logs_for_finding(finding_query, store)
        if not entries:
            console.print("No Ghost Log entries matched that finding.")
            return
        table = Table(title="Ghost Log Finding Correlation")
        for column in ("Time", "Host", "Finding", "Command/Log"):
            table.add_column(column)
        for entry in entries:
            table.add_row(
                entry.date,
                entry.host or "",
                entry.linked_finding_hash or "",
                entry.message,
            )
        console.print(table)
        return
    message, host, tags = _parse_log_args(list(ctx.args))
    if not message:
        raise click.ClickException("Missing log message.")
    add_log(message, host, tuple(tags))


def add_log(message: str, host: str | None = None, tags: tuple[str, ...] = ()) -> None:
    engagement, store = active_workspace()
    entry = {
        "message": message,
        "date": now_iso(),
        "host": host,
        "tags": list(tags),
    }
    store.add_log(entry)
    append_timeline_entry(engagement.notes_dir, entry)
    console.print(f"[✓] Logged: {message}")


@log.command("list")
@click.option("--host")
@click.option("--tag")
@click.option("--today", is_flag=True)
def list_log(host: str | None, tag: str | None, today: bool) -> None:
    """Show log entries."""

    _, store = active_workspace()
    entries = store.get_log({"host": host, "tag": tag, "today": today})
    if not entries:
        console.print("No log entries found.")
        return
    table = Table(title="Attack Log")
    for column in ("Time", "Host", "Message", "Tags"):
        table.add_column(column)
    for item in entries:
        table.add_row(
            item.get("date", ""),
            item.get("host") or "",
            item.get("message", ""),
            ", ".join(item.get("tags", [])),
        )
    console.print(table)


def find_logs_for_finding(
    hash_or_title: str,
    store: WorkspaceStore,
) -> list[WorkspaceLog]:
    """Return Ghost Log entries linked to a finding hash or title fragment."""

    query = hash_or_title.casefold()
    entries = [WorkspaceLog.model_validate(item) for item in store.get_log({})]
    return [
        entry
        for entry in entries
        if entry.linked_finding_hash == hash_or_title
        or query in (entry.message or "").casefold()
    ]


def _parse_log_args(args: list[str]) -> tuple[str, str | None, list[str]]:
    message_parts: list[str] = []
    tags: list[str] = []
    host: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--host" and index + 1 < len(args):
            host = args[index + 1]
            index += 2
            continue
        if arg == "--tag" and index + 1 < len(args):
            tags.append(args[index + 1])
            index += 2
            continue
        message_parts.append(arg)
        index += 1
    return " ".join(message_parts).strip(), host, tags


def _print_status(state: dict, store: WorkspaceStore | None = None) -> None:
    session = state.get("session") or {}
    console.print("Ghost Log Status")
    console.print("─────────────────────────────────────────")
    console.print(f"Status:         {'RUNNING' if state.get('running') else 'STOPPED'}")
    console.print(f"Total sessions: {session.get('total_sessions', 0)}")
    console.print("")
    if state.get("running"):
        started_at = _parse_time(
            str(session.get("started_at") or state.get("started_at"))
        )
        console.print(
            f"Ghost Log: RUNNING (started {_duration_text(started_at, _now())} ago)"
        )
        console.print("This session:")
        console.print(f"  Commands processed: {session.get('commands_seen', 0)}")
        console.print(
            "  Extracted: "
            f"{session.get('credentials_found', 0)} credentials, "
            f"{session.get('findings_found', 0)} findings"
        )
        if last_command := session.get("last_command"):
            last_seen = _parse_time(str(session.get("last_command_at") or ""))
            console.print(
                f"Last command: {last_command} "
                f"({_duration_text(last_seen, _now())} ago)"
            )
    else:
        console.print("Ghost Log: STOPPED")
        console.print("This session:   (not running)")
    if session and not state.get("running"):
        started_at = _parse_time(str(session.get("started_at") or ""))
        stopped_at = _parse_time(str(session.get("stopped_at") or "")) or _now()
        console.print(
            "Last session: "
            f"{started_at.date().isoformat()} "
            f"({_duration_text(started_at, stopped_at)}, "
            f"{_last_history_value(session, 'credentials')} credentials)"
        )
    _print_cumulative_totals(session)
    _print_session_history(session)
    if store is not None:
        _print_quality_stats(store)


def _print_review_queue(store: WorkspaceStore) -> None:
    items = _active_review_items(store)
    console.print(f"Pending Review — {len(items)} items")
    console.print("──────────────────────────────")
    if not items:
        return
    for index, item in enumerate(items, start=1):
        payload = dict(item.get("payload") or {})
        confidence = float(item.get("confidence") or 0.0)
        if item.get("type") == "credential":
            label = payload.get("username") or "unknown credential"
            console.print(
                f"{index}. Credential: {label} (confidence: {confidence:.0%})"
            )
        else:
            label = payload.get("title") or "unknown finding"
            console.print(f"{index}. Finding: {label!r} (confidence: {confidence:.0%})")
        if source := item.get("source_command"):
            console.print(f"   From: {source!r}")
        notes = ", ".join(item.get("validation_notes") or [])
        if notes:
            console.print(f"   Notes: {notes}")
        console.print("   [a]ccept  [r]eject  [e]dit  [s]kip")


def _active_review_items(store: WorkspaceStore) -> list[dict]:
    data = store.load()
    now = _now()
    active_items = []
    for item in data.get("pending_review", []):
        expires_at = _parse_time(str(item.get("expires_at") or ""))
        if expires_at >= now:
            active_items.append(item)
    if len(active_items) != len(data.get("pending_review", [])):
        data["pending_review"] = active_items
        store.save(data)
    return active_items


def _print_quality_stats(store: WorkspaceStore) -> None:
    stats = dict(store.load().get("quality_stats", {}))
    written = int(stats.get("written") or 0)
    queued = int(stats.get("queued") or 0)
    rejected = int(stats.get("rejected") or 0)
    confidence_count = int(stats.get("confidence_count") or 0)
    confidence_total = float(stats.get("confidence_total") or 0.0)
    average = (
        int(round((confidence_total / confidence_count) * 100))
        if confidence_count
        else 0
    )
    console.print("")
    console.print("Quality stats (this engagement):")
    console.print(f"  Written:  {written} (auto-accepted)")
    console.print(f"  Queued:   {queued} (pending review)")
    console.print(f"  Rejected: {rejected} (too low confidence)")
    console.print(f"  Avg confidence: {average}%")


def _print_session_summary(state: dict) -> None:
    session = state.get("session") or {}
    if not session:
        return
    started_at = _parse_time(str(session.get("started_at") or ""))
    stopped_at = _parse_time(str(session.get("stopped_at") or "")) or _now()
    seen = int(session.get("commands_seen") or 0)
    kept = int(session.get("commands_kept") or 0)
    percent = int(round((kept / seen) * 100)) if seen else 0
    vault_updated = any(
        int(session.get(key) or 0)
        for key in ("credentials_found", "findings_found", "log_entries_found")
    )
    console.print("Ghost Log Session Summary")
    console.print("─────────────────────────")
    console.print(f"Duration:       {_duration_text(started_at, stopped_at)}")
    console.print(f"Commands seen:  {seen}")
    console.print(f"Commands kept:  {kept} ({percent}%)")
    console.print("Extracted:")
    console.print(f"  Credentials:  {session.get('credentials_found', 0)}")
    console.print(f"  Findings:     {session.get('findings_found', 0)}")
    console.print(f"  Log entries:  {session.get('log_entries_found', 0)}")
    console.print(f"Vault updated:  {'yes' if vault_updated else 'no'}")


def _print_cumulative_totals(session: dict) -> None:
    seen = int(session.get("cumulative_commands_seen") or 0)
    kept = int(session.get("cumulative_commands_kept") or 0)
    percent = int(round((kept / seen) * 100)) if seen else 0
    console.print("")
    console.print("Engagement totals (all sessions):")
    console.print(f"  Commands seen:   {seen}")
    console.print(f"  Commands kept:   {kept} ({percent}%)")
    console.print(f"  Credentials:     {session.get('cumulative_credentials', 0)}")
    console.print(f"  Findings:        {session.get('cumulative_findings', 0)}")


def _print_session_history(session: dict) -> None:
    history = list(session.get("session_history") or [])
    if not history:
        return
    console.print("")
    console.print("Session history:")
    for index, item in enumerate(history[-5:], 1):
        started = _format_history_time(str(item.get("started") or ""))
        stopped = _format_history_time(str(item.get("stopped") or ""))
        console.print(
            f"  Session {index}: {started} → {stopped} "
            f"({item.get('credentials', 0)} creds, "
            f"{item.get('findings', 0)} findings)"
        )


def _last_history_value(session: dict, key: str) -> int:
    history = list(session.get("session_history") or [])
    if not history:
        return int(session.get(f"{key}_found") or 0)
    return int(history[-1].get(key) or 0)


def _format_history_time(value: str) -> str:
    parsed = _parse_time(value)
    return parsed.strftime("%Y-%m-%d %H:%M")


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return _now()


def _duration_text(start: datetime, end: datetime) -> str:
    seconds = max(0, int((end - start).total_seconds()))
    if seconds < 60:
        return f"{seconds} seconds"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minutes"
    hours = minutes // 60
    return f"{hours} hours"


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)

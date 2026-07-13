"""PentNote command-line interface."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import cast

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pentnote import __version__
from pentnote.ai.ollama import OllamaError, summarize_text
from pentnote.core.engagement import (
    EngagementError,
    init_engagement,
    load_engagement,
    load_findings,
    load_local_config,
    maybe_load_engagement,
    save_engagement_config,
)
from pentnote.core.engine import parse_content
from pentnote.core.fileio import atomic_write_json
from pentnote.core.models import (
    Engagement,
    EngagementType,
    Finding,
    TargetGroup,
    WorkspaceCredential,
)
from pentnote.generators.index import write_index
from pentnote.generators.markdown import _assign_target_group
from pentnote.generators.report import write_report
from pentnote.graph.canvas import write_bloodhound_canvas
from pentnote.graph.layout import LayoutMode
from pentnote.mitre.chain_detector import detect_chains
from pentnote.mitre.coverage import (
    coverage_summary,
    discovered_ttps_by_tactic,
    format_coverage_output,
    tactic_coverage,
    tool_ttp_coverage,
    total_techniques_by_tactic,
)
from pentnote.mitre.navigator import write_navigator_layer
from pentnote.mitre.next_steps import get_contextual_next_steps
from pentnote.parsers.base import ParserError
from pentnote.parsers.detector import available_parsers, score_parsers
from pentnote.runner import has_tool_config, run_raw_only, run_tool
from pentnote.sync.git import sync_once
from pentnote.sync.ignore import ensure_gitignore, missing_required_gitignore_entries
from pentnote.sync.watcher import watch_and_sync
from pentnote.workspace import creds, log, loot, note
from pentnote.workspace.store import (
    WorkspaceStore,
    credential_from_model,
    find_suspected_host_merges,
    loot_from_model,
)

console = Console()


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="pentnote", message="%(prog)s %(version)s")
def main() -> None:
    """Convert pentest tool output into Obsidian Markdown notes."""


main.add_command(creds)
main.add_command(note)
main.add_command(loot)
main.add_command(log)


@main.command()
@click.option("--once", is_flag=True, help="Run one pull/commit/push sync.")
@click.option("--watch", is_flag=True, help="Watch the vault and sync on changes.")
@click.option("--vault", "vault_path", type=click.Path(path_type=Path))
@click.option(
    "--reindex",
    is_flag=True,
    help="Rebuild the Obsidian map of content (standalone; does not run Git sync).",
)
@click.option(
    "--graph",
    "regenerate_graph",
    is_flag=True,
    help=(
        "Regenerate the BloodHound Canvas export (standalone; does not run "
        "Git sync). Requires --bloodhound-json."
    ),
)
@click.option(
    "--bloodhound-json",
    "bloodhound_json",
    type=click.Path(path_type=Path),
    help="BloodHound/SharpHound export used by --graph.",
)
@click.option(
    "--canvas-output",
    "canvas_output",
    type=click.Path(path_type=Path),
    default=Path("Shortest Path to DA.canvas"),
    show_default=True,
    help="Output .canvas file used by --graph.",
)
@click.option(
    "--layout",
    "layout_mode",
    type=click.Choice([mode.value for mode in LayoutMode]),
    default=LayoutMode.AUTO.value,
    show_default=True,
    help="Canvas layout strategy used by --graph.",
)
@click.option(
    "--highlight-paths",
    is_flag=True,
    help="Highlight attack-path edges in the canvas used by --graph.",
)
def sync(
    once: bool,
    watch: bool,
    vault_path: Path | None,
    reindex: bool,
    regenerate_graph: bool,
    bloodhound_json: Path | None,
    canvas_output: Path,
    layout_mode: str,
    highlight_paths: bool,
) -> None:
    """Synchronize the engagement vault with Git.

    On a plain invocation (no --reindex/--graph given), both the Obsidian
    index and the BloodHound Canvas export (if --bloodhound-json is known)
    are refreshed automatically before the Git sync runs. Passing --reindex
    and/or --graph explicitly runs only the requested regeneration(s) and
    skips the Git sync, so either can be used standalone in a vault with no
    Git remote configured.
    """

    if once and watch:
        raise click.ClickException("Use only one of --once or --watch.")
    explicit_action = reindex or regenerate_graph
    if watch and explicit_action:
        raise click.ClickException("--reindex/--graph cannot be combined with --watch.")
    engagement = _active_engagement(vault_path)

    if not watch:
        auto_mode = not explicit_action
        if reindex or auto_mode:
            path = write_index(
                load_findings(engagement),
                engagement.notes_dir,
                engagement_name=engagement.name,
                scope=engagement.scope,
            )
            click.echo(f"wrote: {path}")
        if regenerate_graph or auto_mode:
            if bloodhound_json is not None:
                output_path = canvas_output
                if not output_path.is_absolute():
                    output_path = engagement.root / output_path
                result = write_bloodhound_canvas(
                    bloodhound_json,
                    output_path,
                    vault_root=engagement.root,
                    layout=LayoutMode(layout_mode),
                    highlight_paths=highlight_paths,
                )
                click.echo(f"wrote: {result.written}")
            elif regenerate_graph:
                raise click.ClickException("--graph requires --bloodhound-json PATH.")
        if explicit_action:
            return

    local = load_local_config(engagement)
    remote = str(local.get("sync_remote") or "origin")
    branch = str(local.get("sync_branch") or "")
    if watch:
        try:
            watch_and_sync(engagement.root, remote=remote, branch=branch)
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        return
    try:
        result = sync_once(engagement.root, remote=remote, branch=branch)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    if result.conflicts:
        raise click.ClickException(
            f"{result.message} Conflicts: {', '.join(result.conflicts)}"
        )
    click.echo(result.message)


@main.command()
@click.argument("engagement_name", required=False)
@click.option("--scope", multiple=True, help="Engagement scope CIDR or descriptor.")
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("."),
    show_default=True,
    help="Vault path.",
)
@click.option("--wizard", is_flag=True, help="Prompt for engagement metadata.")
def init(
    engagement_name: str | None,
    scope: tuple[str, ...],
    output_dir: Path,
    wizard: bool,
) -> None:
    """Initialize an engagement vault."""

    if wizard:
        engagement_name, output_dir, metadata_scope, metadata = _prompt_init_wizard(
            engagement_name,
            output_dir,
        )
        engagement_type = cast(EngagementType, metadata["engagement_type"])
        client_name = cast(str | None, metadata.get("client_name"))
        operator_name = cast(str | None, metadata.get("operator"))
        notes = cast(str | None, metadata.get("notes"))
        start_date = str(metadata["start_date"])
        click.echo("")
        click.echo(f"Creating engagement: {engagement_name}")
        click.echo(f"Type: {_engagement_type_long_label(engagement_type)}")
        click.echo(f"Scope: {', '.join(metadata_scope) or 'N/A'}")
        if client_name:
            click.echo(f"Client: {client_name}")
        engagement = init_engagement(
            output_dir,
            engagement_name,
            metadata_scope,
            client_name=client_name,
            engagement_type=engagement_type,
            start_date=start_date,
            operator=operator_name,
            notes=notes,
        )
        click.echo(f"[✓] Vault created at {engagement.root}")
    else:
        if not engagement_name:
            raise click.ClickException("Missing engagement name.")
        engagement = init_engagement(output_dir, engagement_name, list(scope))

    click.echo(f"Initialized engagement: {engagement.name}")
    click.echo(f"Root: {engagement.root}")
    click.echo(f"Notes: {engagement.notes_dir}")
    click.echo(f"Reports: {engagement.reports_dir}")
    click.echo(f"Raw: {engagement.raw_dir}")
    click.echo(f"State: {engagement.state_dir}")


def _prompt_init_wizard(
    engagement_name: str | None,
    output_dir: Path,
) -> tuple[str, Path, list[str], dict[str, object]]:
    """Collect engagement metadata through Click prompts."""

    name = engagement_name or click.prompt("Engagement name").strip()
    client_name = _prompt_optional("Client name (optional)")
    click.echo("Engagement type:")
    engagement_options = [
        (1, EngagementType.INTERNAL_AD, "Internal AD"),
        (2, EngagementType.EXTERNAL_WEB, "External Web"),
        (3, EngagementType.FULL_SCOPE, "Full Scope"),
        (4, EngagementType.RED_TEAM, "Red Team"),
        (5, EngagementType.ASSUMED_BREACH, "Assumed Breach"),
    ]
    for number, _, label in engagement_options:
        click.echo(f"  {number}. {label}")
    choice = click.prompt("Choice", default=3, type=click.IntRange(1, 5))
    engagement_type = next(
        item for number, item, _ in engagement_options if number == choice
    )

    click.echo("Scope (IP/CIDR/domain, one per line, blank to finish):")
    scope_items: list[str] = []
    while True:
        item = click.prompt(">", default="", show_default=False).strip()
        if not item:
            break
        scope_items.append(item)

    metadata = {
        "client_name": client_name,
        "engagement_type": engagement_type,
        "start_date": datetime.now(UTC).date().isoformat(),
        "operator": _prompt_optional("Operator name (optional)"),
        "notes": _prompt_optional("Notes (optional)"),
    }
    target_dir = output_dir
    if output_dir == Path("."):
        target_dir = Path(name)
    return name, target_dir, scope_items, metadata


def _prompt_optional(label: str) -> str | None:
    value = click.prompt(label, default="", show_default=False).strip()
    return value or None


def _engagement_type_short_label(engagement_type: EngagementType | str) -> str:
    labels = {
        EngagementType.INTERNAL_AD: "Internal AD",
        EngagementType.EXTERNAL_WEB: "External Web",
        EngagementType.FULL_SCOPE: "Full Scope",
        EngagementType.RED_TEAM: "Red Team",
        EngagementType.ASSUMED_BREACH: "Assumed Breach",
    }
    return labels[EngagementType(engagement_type)]


def _engagement_type_long_label(engagement_type: EngagementType | str) -> str:
    labels = {
        EngagementType.INTERNAL_AD: "Internal Active Directory",
        EngagementType.EXTERNAL_WEB: "External Web",
        EngagementType.FULL_SCOPE: "Full Scope",
        EngagementType.RED_TEAM: "Red Team",
        EngagementType.ASSUMED_BREACH: "Assumed Breach",
    }
    return labels[EngagementType(engagement_type)]


@main.group()
def targets() -> None:
    """Manage target groups inside an engagement."""


@targets.command("list")
@click.option("--vault", "vault_path", type=click.Path(path_type=Path))
def targets_list(vault_path: Path | None) -> None:
    """List target groups with host, finding, and credential counts."""

    engagement = _active_engagement(vault_path)
    if not engagement.target_groups:
        click.echo("No target groups configured.")
        return
    for row in _target_group_counts(engagement):
        click.echo(
            f"{row['name']}\tscope: {row['scope']}\thosts: {row['hosts']}\t"
            f"findings: {row['findings']}\tcredentials: {row['credentials']}"
        )


@targets.command("add")
@click.argument("name")
@click.option("--scope", "scope_items", multiple=True, required=True)
@click.option("--description", default="", show_default=False)
@click.option("--vault", "vault_path", type=click.Path(path_type=Path))
def targets_add(
    name: str,
    scope_items: tuple[str, ...],
    description: str,
    vault_path: Path | None,
) -> None:
    """Add or update a target group in the active engagement."""

    engagement = _active_engagement(vault_path)
    normalized_name = name.casefold()
    existing = next(
        (
            group
            for group in engagement.target_groups
            if group.name.casefold() == normalized_name
        ),
        None,
    )
    if existing:
        existing.scope = list(dict.fromkeys([*existing.scope, *scope_items]))
        if description:
            existing.description = description
        action = "updated"
    else:
        engagement.target_groups.append(
            TargetGroup(name=name, scope=list(scope_items), description=description)
        )
        action = "added"
    save_engagement_config(engagement)
    click.echo(f"{action} target group: {name}")


@targets.command("show")
@click.argument("name")
@click.option("--vault", "vault_path", type=click.Path(path_type=Path))
def targets_show(name: str, vault_path: Path | None) -> None:
    """Show counts for one target group."""

    engagement = _active_engagement(vault_path)
    rows = _target_group_counts(engagement)
    row = next(
        (item for item in rows if item["name"].casefold() == name.casefold()), None
    )
    if row is None:
        raise click.ClickException(f"Unknown target group: {name}")
    click.echo(f"Target Group: {row['name']}")
    click.echo(f"Scope: {row['scope']}")
    click.echo(f"Hosts: {row['hosts']}")
    click.echo(f"Findings: {row['findings']}")
    click.echo(f"Credentials: {row['credentials']}")
    for severity, count in row["severity_counts"].items():
        click.echo(f"  {severity.title()}: {count}")


def _target_group_counts(engagement: Engagement) -> list[dict[str, object]]:
    findings = load_findings(engagement)
    credentials = WorkspaceStore(engagement.root).get_credentials({})
    hosts = sorted(
        {
            *[host for finding in findings for host in finding.affected_hosts],
            *_host_targets_from_notes(engagement.notes_dir),
        }
    )
    rows: list[dict[str, object]] = []
    for group in engagement.target_groups:
        group_findings = [
            finding for finding in findings if _finding_in_group(finding, group)
        ]
        group_hosts = [
            host for host in hosts if _assign_target_group(host, [group]) == group.name
        ]
        group_credentials = [
            credential
            for credential in credentials
            if _assign_target_group(str(credential.get("source_host", "")), [group])
            == group.name
        ]
        rows.append(
            {
                "name": group.name,
                "scope": ", ".join(group.scope) or "N/A",
                "hosts": len(group_hosts),
                "findings": len(group_findings),
                "credentials": len(group_credentials),
                "severity_counts": _severity_counts_for_findings(group_findings),
            }
        )
    return rows


def _finding_in_group(finding: Finding, group: TargetGroup) -> bool:
    return any(
        _assign_target_group(host, [group]) == group.name
        for host in finding.affected_hosts
    )


def _host_targets_from_notes(notes_dir: Path) -> set[str]:
    host_dir = notes_dir / "hosts"
    if not host_dir.exists():
        return set()
    targets: set[str] = set()
    for path in host_dir.glob("*.md"):
        frontmatter = _read_simple_frontmatter(path)
        for key in ("host", "hostname"):
            value = frontmatter.get(key)
            if value:
                targets.add(value)
    return targets


def _read_simple_frontmatter(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    if not lines or lines[0].strip() != "---":
        return {}
    frontmatter: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        frontmatter[key.strip()] = value.strip().strip("\"'")
    return frontmatter


def _severity_counts_for_findings(findings: Iterable[Finding]) -> dict[str, int]:
    return {
        severity: sum(1 for finding in findings if finding.severity.value == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }


@main.command()
@click.argument("file_or_dir", required=False, type=click.Path(path_type=Path))
@click.option("--tool", "tool_name", help="Force a parser by tool name.")
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path),
    help="Output vault or notes directory.",
)
@click.option("--recursive", is_flag=True, help="Process files recursively.")
@click.option("--ai-summary", is_flag=True, help="Reserved for local AI summaries.")
def parse(
    file_or_dir: Path | None,
    tool_name: str | None,
    output_dir: Path,
    recursive: bool,
    ai_summary: bool,
) -> None:
    """Parse existing tool output you already have (file, stdin, or a
    --recursive directory) without re-running the tool. Use `run` instead
    if you want PentNote to execute the tool for you."""

    engagement = _resolve_engagement(output_dir)
    target_dir = output_dir or Path("notes")
    inputs = _collect_inputs(file_or_dir, recursive)
    all_written: list[Path] = []
    failures: list[tuple[str, str]] = []

    for input_path in inputs:
        try:
            content, source_name = _read_input(input_path)
            outcome = parse_content(
                content,
                target_dir,
                tool_name=tool_name,
                engagement=engagement,
            )
        except (
            ParserError,
            EngagementError,
            click.ClickException,
            click.FileError,
        ) as exc:
            source_name = str(input_path) if input_path is not None else "-"
            if not recursive:
                if isinstance(exc, (ParserError, EngagementError)):
                    raise click.ClickException(str(exc)) from exc
                raise
            failures.append((source_name, str(exc)))
            continue
        if engagement:
            store = WorkspaceStore(engagement.root)
            for credential in outcome.result.credentials:
                store.add_credential(
                    credential_from_model(credential, outcome.result.tool)
                )
            for loot_item in outcome.result.loot:
                store.add_loot(loot_from_model(loot_item))
        all_written.extend(outcome.written)
        partial = " partial" if outcome.result.partial else ""
        click.echo(
            f"Parser: {outcome.result.tool} | hosts: {len(outcome.result.hosts)} | "
            f"findings: {len(outcome.result.findings)} | "
            f"new: {outcome.new_findings} | duplicates: {outcome.duplicate_findings} | "
            f"loot: {len(outcome.result.loot)} | "
            f"source: {source_name}{partial}"
        )
        if ai_summary:
            try:
                click.echo(summarize_text(content))
            except OllamaError as exc:
                if not recursive:
                    raise click.ClickException(str(exc)) from exc
                failures.append((source_name, str(exc)))

    for path in all_written:
        click.echo(f"wrote: {path}")
    if failures:
        for source_name, error in failures:
            click.echo(f"[!] {source_name}: {error}", err=True)
        raise click.ClickException(
            f"{len(failures)} file(s) failed; {len(inputs) - len(failures)} parsed."
        )


@main.command(
    "run",
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
    },
)
@click.argument("tool_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--tool", "parser_override", default=None, help="Override parser name.")
@click.option("--no-parse", is_flag=True, help="Save raw output only, skip parsing.")
@click.option(
    "--no-universal",
    is_flag=True,
    help="Skip parsing if no specific parser is configured for the tool.",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress tool output.")
def run_cmd(
    tool_args: tuple[str, ...],
    parser_override: str | None,
    no_parse: bool,
    no_universal: bool,
    quiet: bool,
) -> None:
    """Run a pentest tool, save raw output, and auto-parse."""

    if not tool_args:
        click.echo("Usage: pentnote run TOOL [ARGS...]")
        return

    engagement = maybe_load_engagement()
    vault_root = engagement.root if engagement else Path.cwd()
    tool = tool_args[0]
    args = list(tool_args[1:])

    if no_parse:
        result = run_raw_only(tool, args, vault_root, quiet=quiet)
        click.echo("")
        click.echo(f"saved:  {result.raw_path}")
        if result.terminal_path:
            click.echo(f"saved:  {result.terminal_path}")
        return

    if no_universal and parser_override is None and not has_tool_config(tool):
        result = run_raw_only(tool, args, vault_root, quiet=quiet)
        click.echo("")
        click.echo(f"[!] No parser for {tool!r} — raw saved only")
        click.echo(f"saved:  {result.raw_path}")
        if result.terminal_path:
            click.echo(f"saved:  {result.terminal_path}")
        return

    try:
        result = run_tool(
            tool,
            args,
            vault_root,
            parser_override=parser_override,
            engagement=engagement,
            quiet=quiet,
        )
    except (ParserError, EngagementError) as exc:
        raise click.ClickException(str(exc)) from exc

    if engagement:
        store = WorkspaceStore(engagement.root)
        for credential in result.outcome.result.credentials:
            store.add_credential(
                credential_from_model(credential, result.outcome.result.tool)
            )
        for loot_item in result.outcome.result.loot:
            store.add_loot(loot_from_model(loot_item))

    click.echo("")
    click.echo(f"saved:  {result.raw_path}")
    if result.terminal_path:
        click.echo(f"saved:  {result.terminal_path}")
    click.echo(
        f"parser: {result.parser} | "
        f"hosts: {len(result.outcome.result.hosts)} | "
        f"findings: {len(result.outcome.result.findings)} | "
        f"new: {result.outcome.new_findings} | "
        f"duplicates: {result.outcome.duplicate_findings} | "
        f"loot: {len(result.outcome.result.loot)}"
    )
    for path in result.outcome.written:
        click.echo(f"wrote:  {path}")


@main.command()
@click.option(
    "--parsers",
    "show_parsers",
    is_flag=True,
    help="List available parsers and their aliases/extensions.",
)
@click.option(
    "--parsers-detect",
    "parsers_detect_file",
    type=click.Path(path_type=Path),
    help="Show parser auto-detection scores for FILE.",
)
@click.option(
    "--health",
    "show_health",
    is_flag=True,
    help="Check engagement workspace health instead of the summary.",
)
@click.option(
    "--fix", is_flag=True, help="With --health, repair missing safe defaults."
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="With --health --fix, preview fixes without changing files.",
)
@click.option(
    "--include-low",
    is_flag=True,
    help="With --health --fix, also apply low-severity cleanup fixes.",
)
@click.option(
    "--check-merges",
    "check_merges",
    is_flag=True,
    help=(
        "With --health, flag host notes that the pre-1.1.0 rule may have merged "
        "on hostname string-equality alone, for manual review (read-only)."
    ),
)
@click.argument("vault_path", required=False, type=click.Path(path_type=Path))
def status(
    vault_path: Path | None,
    show_parsers: bool,
    parsers_detect_file: Path | None,
    show_health: bool,
    fix: bool,
    dry_run: bool,
    include_low: bool,
    check_merges: bool,
) -> None:
    """Show the current engagement summary."""

    if show_parsers or parsers_detect_file:
        if show_parsers:
            for parser in available_parsers():
                aliases = ", ".join(parser.aliases) if parser.aliases else "-"
                extensions = (
                    ", ".join(parser.supported_extensions)
                    if parser.supported_extensions
                    else "-"
                )
                click.echo(f"{parser.tool_name}\taliases: {aliases}\text: {extensions}")
        if parsers_detect_file:
            content, _ = _read_input(parsers_detect_file)
            scores = [score for score in score_parsers(content) if score.score > 0]
            if not scores:
                raise click.ClickException("No parser recognized this input.")
            for score in scores[:5]:
                click.echo(f"{score.parser.tool_name}: {score.score:.0%}")
        return

    if show_health or fix or dry_run or include_low or check_merges:
        engagement = _active_engagement(vault_path)
        issues = _doctor_issues(engagement)
        if fix or dry_run:
            _apply_doctor_fixes(issues, dry_run=dry_run, include_low=include_low)
        else:
            _print_doctor_issues(issues)
        if not any(issue["code"] == "findings_json_corrupt" for issue in issues):
            _check_json(engagement.findings_path, "findings")
        if not any(issue["code"] == "workspace_json_corrupt" for issue in issues):
            workspace_path = engagement.root / ".pentnote" / "workspace.json"
            if workspace_path.exists():
                _check_json(workspace_path, "workspace")
            else:
                click.echo("[✓] workspace: not created yet")
        _check_json(engagement.config_path, "config")
        for path in (engagement.notes_dir, engagement.reports_dir, engagement.raw_dir):
            click.echo(
                f"[✓] {path.relative_to(engagement.root)}: exists"
                if path.exists()
                else f"[✗] {path}: missing"
            )
        if check_merges:
            _print_suspected_merges(engagement.notes_dir)
        return

    engagement = _active_engagement(vault_path)
    findings = load_findings(engagement)
    store = WorkspaceStore(engagement.root)
    credentials = store.get_credentials({})
    hosts = sorted({host for finding in findings for host in finding.affected_hosts})
    chains = detect_chains(findings)
    console.print(f"PentNote v{__version__}")
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row(
        "Engagement",
        f"{engagement.name} ({_engagement_type_short_label(engagement.engagement_type)})",
    )
    if engagement.client_name:
        summary.add_row("Client", engagement.client_name)
    summary.add_row("Scope", ", ".join(engagement.scope) or "N/A")
    summary.add_row("Hosts", str(len(hosts)))
    summary.add_row("Credentials", str(len(credentials)))
    summary.add_row("Findings", str(len(findings)))
    summary.add_row("Chains", str(len(chains)))
    console.print(Panel(summary, title="PentNote Status", expand=False))

    severity_table = Table(title="Severity Breakdown")
    severity_table.add_column("Severity")
    severity_table.add_column("Count", justify="right")
    for severity in ("critical", "high", "medium", "low", "info"):
        count = sum(1 for finding in findings if finding.severity.value == severity)
        severity_table.add_row(severity.title(), str(count))
    console.print(severity_table)

    if chains:
        chain_table = Table(title="Attack Chains")
        chain_table.add_column("Severity")
        chain_table.add_column("Chain")
        for chain in chains:
            chain_table.add_row(chain.severity, f"{chain.label} <- DETECTED")
        console.print(chain_table)


def _check_json(path: Path, label: str) -> None:
    try:
        json_text = path.read_text(encoding="utf-8")
        json.loads(json_text)
    except FileNotFoundError:
        click.echo(f"[✗] {label}: missing")
    except json.JSONDecodeError as exc:
        click.echo(f"[✗] {label}: invalid JSON ({exc})")
    else:
        click.echo(f"[✓] {label}: valid")


DoctorFix = Callable[[bool], str]


def _doctor_issues(engagement: Engagement) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    missing_gitignore = missing_required_gitignore_entries(engagement.root)
    for entry in missing_gitignore:
        name = Path(entry).name
        code = (
            "local_json_not_in_gitignore"
            if name == "local.json"
            else "workspace_json_not_in_gitignore"
        )
        issues.append(
            _doctor_issue(
                code,
                "high",
                f"{name} not in .gitignore",
                _fix_gitignore(engagement.root, entry),
            )
        )

    workspace_path = engagement.root / ".pentnote" / "workspace.json"
    if workspace_path.exists() and not _json_valid(workspace_path):
        issues.append(
            _doctor_issue(
                "workspace_json_corrupt",
                "critical",
                "workspace.json is corrupt",
                _backup_and_reset_json(
                    workspace_path,
                    {"credentials": [], "notes": [], "loot": [], "log": []},
                    "workspace.json backed up and reset",
                    chmod_0600=True,
                ),
            )
        )
    elif workspace_path.exists() and workspace_path.stat().st_mode & 0o077:
        mode = oct(workspace_path.stat().st_mode & 0o777)
        issues.append(
            _doctor_issue(
                "workspace_json_wrong_permissions",
                "medium",
                f"workspace.json permissions: {mode} (should be 0o600)",
                _fix_workspace_permissions(workspace_path),
            )
        )

    if not _json_valid(engagement.findings_path):
        issues.append(
            _doctor_issue(
                "findings_json_corrupt",
                "critical",
                "findings.json is corrupt",
                _backup_and_reset_json(
                    engagement.findings_path,
                    [],
                    "findings.json backed up and reset",
                ),
            )
        )

    orphaned = _orphaned_finding_notes(engagement)
    if orphaned:
        issues.append(
            _doctor_issue(
                "orphaned_finding_notes",
                "low",
                f"{len(orphaned)} orphaned finding notes",
                _cleanup_orphaned_notes(orphaned),
            )
        )

    if _rules_json_has_duplicate_ttps():
        issues.append(
            _doctor_issue(
                "duplicate_ttp_in_rules",
                "low",
                "duplicate TTP IDs in rules.json",
                _deduplicate_rules_json,
            )
        )
    return issues


def _doctor_issue(
    code: str,
    severity: str,
    description: str,
    fix_func: DoctorFix,
) -> dict[str, object]:
    return {
        "code": code,
        "severity": severity,
        "description": description,
        "fix": fix_func,
    }


def _print_suspected_merges(notes_dir: Path) -> None:
    """Report host notes that the pre-1.1.0 rule may have merged (read-only)."""

    flagged = find_suspected_host_merges(notes_dir)
    if not flagged:
        click.echo("[✓] host-merge check: no name collisions across host notes")
        return
    click.echo(
        f"[!] host-merge check: {len(flagged)} host note(s) share a name with "
        "another host but no IP link — review for a pre-1.1.0 merge:"
    )
    for suspect in flagged:
        identity = suspect.hostname or suspect.ip or suspect.note_path.stem
        rel = suspect.note_path.name
        click.echo(
            f"    [{suspect.confidence.upper()}] {rel} ({identity}, ip={suspect.ip or 'N/A'})"
            f" collides with: {', '.join(suspect.collisions)}"
        )
    click.echo(
        "    Read-only: verify each note and split by hand if two hosts were "
        "conflated. Nothing was changed."
    )


def _print_doctor_issues(issues: list[dict[str, object]]) -> None:
    if not issues:
        click.echo("[✓] No fixable issues found")
        return
    for issue in issues:
        severity = str(issue["severity"]).upper()
        description = str(issue["description"])
        if issue["code"] == "local_json_not_in_gitignore":
            click.echo(
                "[!] local.json not in .gitignore — run pentnote status --health --fix"
            )
        else:
            click.echo(f"[{severity}] {description}")
    click.echo("Run pentnote status --health --fix to fix issues automatically.")


def _apply_doctor_fixes(
    issues: list[dict[str, object]],
    *,
    dry_run: bool,
    include_low: bool,
) -> None:
    if not issues:
        click.echo("[✓] No fixable issues found")
        return
    for issue in issues:
        description = str(issue["description"])
        if issue["severity"] == "low" and not include_low:
            click.echo(f"[!] Skipped: {description} (use --fix --include-low)")
            continue
        fix_func = issue["fix"]
        if not callable(fix_func):
            continue
        message = fix_func(dry_run)
        prefix = "Would fix:" if dry_run else "[✓] Fixed:"
        click.echo(f"{prefix} {message}")


def _json_valid(path: Path) -> bool:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    return True


def _fix_gitignore(root: Path, entry: str) -> DoctorFix:
    def fix(dry_run: bool) -> str:
        if not dry_run:
            ensure_gitignore(root)
        return f"add {entry} to .gitignore"

    return fix


def _fix_workspace_permissions(path: Path) -> DoctorFix:
    def fix(dry_run: bool) -> str:
        if not dry_run and os.name != "nt":
            os.chmod(path, 0o600)
        return "workspace.json permissions set to 0o600"

    return fix


def _backup_and_reset_json(
    path: Path,
    empty_value: object,
    message: str,
    *,
    chmod_0600: bool = False,
) -> DoctorFix:
    def fix(dry_run: bool) -> str:
        backup = path.with_suffix(f"{path.suffix}.corrupt.{_doctor_timestamp()}")
        if not dry_run:
            if path.exists():
                path.replace(backup)
            atomic_write_json(path, empty_value)
            if chmod_0600 and os.name != "nt":
                os.chmod(path, 0o600)
        return f"{message} → {backup.name}"

    return fix


def _orphaned_finding_notes(engagement: Engagement) -> list[Path]:
    finding_dir = engagement.notes_dir / "findings"
    if not finding_dir.exists() or not _json_valid(engagement.findings_path):
        return []
    findings = json.loads(engagement.findings_path.read_text(encoding="utf-8"))
    known_hashes = {
        str(item.get("hash"))
        for item in findings
        if isinstance(item, dict) and item.get("hash")
    }
    orphaned = []
    for path in finding_dir.glob("*.md"):
        note_hash = path.stem.split("-", 1)[0]
        if note_hash not in known_hashes:
            orphaned.append(path)
    return sorted(orphaned)


def _cleanup_orphaned_notes(paths: list[Path]) -> DoctorFix:
    def fix(dry_run: bool) -> str:
        if not dry_run:
            for path in paths:
                path.unlink(missing_ok=True)
        return f"removed {len(paths)} orphaned finding note(s)"

    return fix


def _rules_json_has_duplicate_ttps() -> bool:
    rules_path = resources.files("pentnote.mitre.data").joinpath("rules.json")
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    return any(len(values) != len(set(values)) for values in data.values())


def _deduplicate_rules_json(dry_run: bool) -> str:
    rules_path = Path(resources.files("pentnote.mitre.data").joinpath("rules.json"))
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    deduped = {key: list(dict.fromkeys(values)) for key, values in data.items()}
    if not dry_run:
        atomic_write_json(rules_path, deduped)
    return "deduplicate TTP IDs in rules.json"


def _doctor_timestamp() -> int:
    return int(datetime.now(UTC).timestamp())


@main.group()
def mitre() -> None:
    """MITRE ATT&CK views for the active engagement."""


@mitre.command("show")
def mitre_show() -> None:
    """Show all discovered TTPs."""

    findings = _active_findings()
    techniques = sorted(
        {match.technique_id for finding in findings for match in finding.mitre_matches}
    )
    for technique in techniques:
        click.echo(technique)


@mitre.command("export")
@click.option("--format", "export_format", default="navigator", show_default=True)
def mitre_export(export_format: str) -> None:
    """Export MITRE data."""

    if export_format != "navigator":
        raise click.ClickException("Only navigator export is supported.")
    engagement = _active_engagement()
    path = write_navigator_layer(
        load_findings(engagement),
        engagement.reports_dir / "layer.json",
        engagement.name,
    )
    click.echo(f"wrote: {path}")


@mitre.command("chains")
def mitre_chains() -> None:
    """Show detected attack chains."""

    for chain in detect_chains(_active_findings()):
        click.echo(f"{chain.severity}: {chain.label} - {chain.message}")


@mitre.command("coverage")
@click.option("--tool", "show_tool", is_flag=True, help="Show built-in TTP coverage.")
@click.option(
    "--engagement",
    "engagement_only",
    is_flag=True,
    help="Only show tactics with discovered engagement TTPs.",
)
def mitre_coverage(show_tool: bool, engagement_only: bool) -> None:
    """Show tactic coverage percentages."""

    if show_tool:
        coverage = tool_ttp_coverage()
        summary = coverage_summary()
        for source, ttps in coverage.items():
            suffix = f" ({len(ttps)} TTPs)" if ttps else " (0 TTPs)"
            click.echo(f"{source:<20} {', '.join(ttps) if ttps else 'N/A'}{suffix}")
        click.echo(f"Total unique TTPs: {summary['unique_count']}")
        click.echo(f"ATT&CK total: {summary['attack_total']} techniques")
        click.echo(f"Coverage: {summary['coverage_percent']}%")
        click.echo(
            "Coverage gaps (high-value TTPs not covered): " f"{len(summary['gaps'])}"
        )
        for technique_id, name in summary["gap_details"][:5]:
            click.echo(f"  {technique_id} {name}")
        return

    findings = _active_findings()
    coverage = tactic_coverage(findings)
    discovered = discovered_ttps_by_tactic(findings)
    totals = total_techniques_by_tactic()
    if engagement_only:
        coverage = {
            tactic: percent
            for tactic, percent in coverage.items()
            if discovered.get(tactic)
        }
        discovered = {tactic: ttps for tactic, ttps in discovered.items() if ttps}

    for line in format_coverage_output(coverage, discovered, totals):
        click.echo(line)


@mitre.command("next")
@click.option(
    "--show-secret",
    is_flag=True,
    help="Show plaintext secrets in generated commands.",
)
def mitre_next(show_secret: bool) -> None:
    """Show suggested next steps."""

    engagement = maybe_load_engagement()
    findings = load_findings(engagement) if engagement else []
    workspace = WorkspaceStore(engagement.root) if engagement else None
    credentials = (
        [
            WorkspaceCredential.model_validate(credential)
            for credential in workspace.get_credentials({})
        ]
        if workspace
        else []
    )
    hosts = sorted({host for finding in findings for host in finding.affected_hosts})
    ttps = sorted(
        {match.technique_id for finding in findings for match in finding.mitre_matches}
    )

    for step in get_contextual_next_steps(
        ttps,
        findings,
        credentials,
        hosts,
        show_secret=show_secret,
    ):
        click.echo(f"- {step}")


@main.command()
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["markdown", "html", "both"]),
    default="markdown",
    show_default=True,
)
@click.option("--with-defenses", is_flag=True, help="Include D3FEND mappings.")
@click.option(
    "--redact", is_flag=True, help="Redact raw evidence in generated reports."
)
@click.option("--vault", "vault_path", type=click.Path(path_type=Path))
@click.option(
    "--compare-vault",
    type=click.Path(path_type=Path),
    help="Previous engagement vault for fixed-finding context.",
)
def report(
    report_format: str,
    with_defenses: bool,
    redact: bool,
    vault_path: Path | None,
    compare_vault: Path | None,
) -> None:
    """Generate a final report."""

    engagement = _active_engagement(vault_path)
    previous_findings = (
        load_findings(load_engagement(compare_vault)) if compare_vault else None
    )
    paths = write_report(
        load_findings(engagement),
        engagement.reports_dir,
        engagement_name=engagement.name,
        report_format=report_format,
        with_defenses=with_defenses,
        redact=redact,
        engagement=engagement,
        previous_findings=previous_findings,
    )
    for path in paths:
        click.echo(f"wrote: {path}")


def _collect_inputs(file_or_dir: Path | None, recursive: bool) -> list[Path | None]:
    if file_or_dir is None or str(file_or_dir) == "-":
        return [None]
    if file_or_dir.is_dir():
        if not recursive:
            raise click.ClickException(
                "Directory input requires --recursive in this phase."
            )
        return sorted(path for path in file_or_dir.rglob("*") if path.is_file())
    return [file_or_dir]


def _read_input(input_path: Path | None) -> tuple[str, str]:
    if input_path is None:
        return sys.stdin.read(), "-"
    try:
        return input_path.read_text(encoding="utf-8", errors="replace"), str(input_path)
    except OSError as exc:
        raise click.FileError(str(input_path), hint=str(exc)) from exc


def _resolve_engagement(output_dir: Path | None) -> Engagement | None:
    if output_dir and (output_dir / ".pentnote" / "config.json").exists():
        return maybe_load_engagement(output_dir)
    if output_dir is None:
        return maybe_load_engagement()
    return None


def _active_engagement(vault_path: Path | None = None) -> Engagement:
    try:
        return load_engagement(vault_path)
    except EngagementError as exc:
        raise click.ClickException(str(exc)) from exc


def _active_findings() -> list[Finding]:
    try:
        return load_findings(_active_engagement())
    except EngagementError as exc:
        raise click.ClickException(str(exc)) from exc


cli = main


if __name__ == "__main__":
    main()

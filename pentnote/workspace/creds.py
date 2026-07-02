"""Credential workspace commands."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from pentnote.core.cracking import import_hashcat_potfile
from pentnote.core.models import SECRET_TYPE_ALIASES, normalize_secret_type_value
from pentnote.workspace.store import active_workspace, write_credentials_csv

console = Console()

SECRET_TYPES = sorted(set(SECRET_TYPE_ALIASES.values()) | {"hash"})
HASHCAT_MODES: dict[str, int] = {
    "ntlm": 1000,
    "net-ntlmv2": 5600,
    "net-ntlmv1": 5500,
    "sha256": 1400,
    "sha1": 100,
    "md5": 0,
    "bcrypt": 3200,
    "kerberos": 13100,
    "aes256": 19600,
    "dpapi": 15300,
}
HASHCAT_GUIDANCE: dict[str, dict[str, object]] = {
    "ntlm": {
        "mode": 1000,
        "wordlists": [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/"
            "10-million-password-list-top-1000000.txt",
        ],
        "rules": ["best64", "dive"],
        "estimate": "NTLM: ~1 billion hashes/sec on RTX 3080",
        "commands": [
            "hashcat --username -m 1000 {file} rockyou.txt",
            "hashcat --username -m 1000 {file} rockyou.txt -r best64.rule",
            "hashcat --username -m 1000 {file} rockyou.txt --show",
        ],
    },
    "net-ntlmv2": {
        "mode": 5600,
        "wordlists": ["/usr/share/wordlists/rockyou.txt"],
        "rules": ["best64"],
        "estimate": "Net-NTLMv2: ~50M hashes/sec on RTX 3080",
        "commands": [
            "hashcat --username -m 5600 {file} rockyou.txt",
            "hashcat --username -m 5600 {file} rockyou.txt -r best64.rule",
        ],
    },
    "kerberos": {
        "mode": 13100,
        "wordlists": ["/usr/share/wordlists/rockyou.txt"],
        "rules": ["best64", "dive"],
        "estimate": "Kerberos TGS: ~1M hashes/sec on RTX 3080",
        "commands": [
            "hashcat --username -m 13100 {file} rockyou.txt",
        ],
    },
    "sha256": {
        "mode": 1400,
        "wordlists": ["/usr/share/wordlists/rockyou.txt"],
        "rules": ["best64"],
        "estimate": "SHA-256: ~3 billion hashes/sec on RTX 3080",
        "commands": [
            "hashcat --username -m 1400 {file} rockyou.txt",
        ],
    },
}


@click.group()
def creds() -> None:
    """Credential workspace."""


@creds.command("add")
@click.argument("username")
@click.option("--secret", required=True, help="Password, hash, ticket, or token value.")
@click.option(
    "--type",
    "secret_type",
    required=True,
    help="Credential secret type.",
)
@click.option("--host", "source_host", required=True, help="Source host or target.")
@click.option("--domain")
@click.option("--tag", "tags", multiple=True)
@click.option("--notes", default="")
def add_credential(
    username: str,
    secret: str,
    secret_type: str,
    source_host: str,
    domain: str | None,
    tags: tuple[str, ...],
    notes: str,
) -> None:
    """Add a manually discovered credential."""

    _, store = active_workspace()
    secret_type = normalize_secret_type_value(secret_type)
    store.add_credential(
        {
            "username": username,
            "domain": domain,
            "secret": secret,
            "secret_type": secret_type,
            "source_host": source_host,
            "source_tool": "manual",
            "cracked": False,
            "cracked_value": None,
            "tags": list(tags),
            "notes": notes,
        }
    )
    console.print(f"[✓] Credential added: {username}")


@creds.command("list")
@click.option("--type", "secret_type")
@click.option("--cracked", is_flag=True)
@click.option("--uncracked", is_flag=True)
@click.option("--host", "source_host")
@click.option("--domain")
@click.option("--user")
@click.option("--tag")
@click.option("--tool", "source_tool")
@click.option("--show-secret", is_flag=True)
def list_credentials(
    secret_type: str | None,
    cracked: bool,
    uncracked: bool,
    source_host: str | None,
    domain: str | None,
    user: str | None,
    tag: str | None,
    source_tool: str | None,
    show_secret: bool,
) -> None:
    """Show workspace credentials."""

    _, store = active_workspace()
    secret_type = normalize_secret_type_value(secret_type) if secret_type else None
    credentials = store.get_credentials(
        {
            "type": secret_type,
            "cracked": cracked,
            "uncracked": uncracked,
            "host": source_host,
            "domain": domain,
            "user": user,
            "tag": tag,
            "tool": source_tool,
        }
    )
    if not credentials:
        console.print("No credentials found. Run pentnote parse first.")
        return

    table = Table(title="Credentials")
    columns = ["#", "Username", "Domain", "Type", "Source Host", "Cracked", "Tags"]
    if show_secret:
        columns.append("Secret")
    for column in columns:
        table.add_column(column)
    if cracked:
        table.add_column("Plaintext Value")
    for index, item in enumerate(credentials, 1):
        style = {"ntlm": "yellow", "plaintext": "green", "kerberos": "cyan"}.get(
            item.get("secret_type", ""),
            "",
        )
        row = [
            str(index),
            item.get("username", ""),
            item.get("domain") or "",
            (
                f"[{style}]{item.get('secret_type', '')}[/{style}]"
                if style
                else item.get("secret_type", "")
            ),
            item.get("source_host", ""),
            "✓" if item.get("cracked") else "✗",
            ", ".join(item.get("tags", [])),
        ]
        if cracked:
            row.append(item.get("cracked_value") or "")
        if show_secret:
            row.append(_display_secret(item))
        table.add_row(*row)
    console.print(table)


@creds.command()
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["hashcat", "john", "wordlist", "spray", "csv"]),
    required=True,
)
@click.option("--type", "secret_type")
@click.option("--output", "output_path", type=click.Path(path_type=Path))
def export(
    export_format: str, secret_type: str | None, output_path: Path | None
) -> None:
    """Export credentials."""

    engagement, store = active_workspace()
    secret_type = normalize_secret_type_value(secret_type) if secret_type else None
    credentials = store.get_credentials({"type": secret_type})
    lines: list[str] = []
    if export_format == "hashcat":
        lines.extend(_hashcat_lines(credentials))
    elif export_format == "john":
        for item in credentials:
            if item.get("secret_type") != "plaintext" and item.get("secret"):
                lines.append(f"{item.get('username')}:{item.get('secret')}")
    elif export_format == "wordlist":
        lines.extend(
            sorted(
                {item.get("username") for item in credentials if item.get("username")}
            )
        )
    elif export_format == "spray":
        lines.extend(_spray_line(item) for item in credentials if _spray_line(item))
    elif export_format == "csv":
        path = output_path or engagement.reports_dir / "credentials.csv"
        path = write_credentials_csv(path, credentials)
        console.print(f"[✓] wrote: {path}")
        return
    _write_or_echo(lines, output_path)
    if export_format == "hashcat" and output_path and secret_type:
        _print_hashcat_guidance(secret_type, _hashcat_count(credentials), output_path)


@creds.command("crack-status")
def crack_status() -> None:
    """Show credential cracking progress."""

    _, store = active_workspace()
    credentials = store.get_credentials({})
    total = len(credentials)
    cracked = sum(1 for item in credentials if item.get("cracked"))
    uncracked = total - cracked
    percent = int(round((cracked / total) * 100)) if total else 0

    console.print("Credential Cracking Status")
    console.print("──────────────────────────────────────")
    console.print(f"Total credentials:   {total}")
    console.print(f"Cracked:             {cracked}  ({percent}%)")
    console.print(f"Uncracked:           {uncracked}")

    by_type: dict[str, dict[str, int]] = {}
    for item in credentials:
        secret_type = item.get("secret_type") or "unknown"
        bucket = by_type.setdefault(secret_type, {"total": 0, "cracked": 0})
        bucket["total"] += 1
        if item.get("cracked"):
            bucket["cracked"] += 1

    if by_type:
        console.print("")
        console.print("By type:")
        for secret_type in sorted(by_type):
            counts = by_type[secret_type]
            type_percent = (
                int(round((counts["cracked"] / counts["total"]) * 100))
                if counts["total"]
                else 0
            )
            console.print(
                f"  {secret_type:<12} {counts['total']} total, "
                f"{counts['cracked']} cracked ({type_percent}%)"
            )

    uncracked_types = sorted(
        {
            item.get("secret_type")
            for item in credentials
            if item.get("secret")
            and not item.get("cracked")
            and item.get("secret_type")
            and item.get("secret_type") != "plaintext"
        }
    )
    if uncracked_types:
        console.print("")
        console.print("Uncracked hashes ready to export:")
        for secret_type in uncracked_types:
            click.echo(
                "  pentnote creds export --format hashcat "
                f"--type {secret_type} --output {secret_type}_remaining.txt"
            )


@creds.command()
@click.argument("username")
@click.option("--cracked", "plaintext", required=True)
def update(username: str, plaintext: str) -> None:
    """Mark a credential as cracked."""

    _, store = active_workspace()
    data = store.load()
    matches = [
        (index, item)
        for index, item in enumerate(data["credentials"])
        if item.get("username", "").casefold() == username.casefold()
    ]
    if not matches:
        raise click.ClickException(f"No credential found for username: {username}")
    selected = matches[0]
    if len(matches) > 1:
        choice = click.prompt("Multiple matches found. Choose #", type=int, default=1)
        selected = matches[choice - 1]
    index, item = selected
    item["cracked"] = True
    item["cracked_value"] = plaintext
    data["credentials"][index] = item
    store.save(data)
    console.print(f"[✓] Updated {item['username']} → {plaintext}")


@creds.command("sync-pot")
@click.argument("potfile_path", type=click.Path(path_type=Path))
def sync_pot(potfile_path: Path) -> None:
    """Sync cracked Hashcat potfile entries into the workspace."""

    engagement, _store = active_workspace()
    result = import_hashcat_potfile(str(potfile_path), engagement=engagement)
    console.print(
        "[✓] Hashcat sync: "
        f"parsed={result.parsed} matched={result.matched} "
        f"updated={result.updated} findings={result.findings_created}"
    )
    for credential in result.credentials:
        principal = (
            f"{credential.domain}\\{credential.username}"
            if credential.domain
            else credential.username
        )
        console.print(f"  cracked: {principal}")


@creds.command()
@click.argument("username")
@click.argument("tag")
def tag(username: str, tag: str) -> None:
    """Add a tag to a credential."""

    _update_credential_field(username, "tags", tag)


@creds.command("note")
@click.argument("username")
@click.argument("text")
def note_credential(username: str, text: str) -> None:
    """Add a note to a credential."""

    _update_credential_field(username, "notes", text)


def _update_credential_field(username: str, field: str, value: str) -> None:
    _, store = active_workspace()
    data = store.load()
    for item in data["credentials"]:
        if item.get("username", "").casefold() != username.casefold():
            continue
        if field == "tags":
            item.setdefault("tags", [])
            if value not in item["tags"]:
                item["tags"].append(value)
        else:
            item["notes"] = (item.get("notes", "") + "\n" + value).strip()
        store.save(data)
        console.print(f"[✓] Updated {item['username']}")
        return
    raise click.ClickException(f"No credential found for username: {username}")


def _display_secret(item: dict) -> str:
    return item.get("cracked_value") or item.get("secret") or ""


def _spray_line(item: dict) -> str:
    password = item.get("cracked_value")
    if not password and item.get("secret_type") == "plaintext":
        password = item.get("secret")
    username = item.get("username")
    return f"{username}:{password}" if username and password else ""


def _hashcat_lines(credentials: list[dict]) -> list[str]:
    lines: list[str] = []
    emitted_modes: set[int] = set()
    for item in credentials:
        if item.get("secret_type") == "plaintext" or not item.get("secret"):
            continue
        mode = HASHCAT_MODES.get(item.get("secret_type", ""), 1000)
        if mode not in emitted_modes:
            lines.append(f"# hashcat -m {mode} hashes.txt rockyou.txt")
            emitted_modes.add(mode)
        lines.append(f"{item.get('username')}:{item.get('secret')}")
    return lines


def _hashcat_count(credentials: list[dict]) -> int:
    return sum(
        1
        for item in credentials
        if item.get("secret_type") != "plaintext" and item.get("secret")
    )


def _print_hashcat_guidance(
    secret_type: str,
    count: int,
    output_file: Path,
) -> None:
    guide = HASHCAT_GUIDANCE.get(secret_type)
    if not guide or count == 0:
        return

    click.echo("")
    click.echo("Hashcat Guidance:")
    click.echo(f"  Mode:     -m {guide.get('mode', '?')}")
    click.echo(f"  Hashes:   {count}")
    click.echo(f"  Estimate: {guide.get('estimate', 'unknown')}")

    wordlists = guide.get("wordlists") or []
    if wordlists:
        click.echo("")
        click.echo("  Suggested wordlists:")
        for wordlist in wordlists:
            click.echo(f"    {wordlist}")

    rules = guide.get("rules") or []
    if rules:
        click.echo("")
        click.echo("  Suggested rules:")
        for rule in rules:
            click.echo(f"    {rule}")

    click.echo("")
    click.echo("  Suggested commands:")
    for command in guide.get("commands", []):
        click.echo(f"    {str(command).format(file=output_file)}")
    click.echo("")
    click.echo(
        "  Sync cracked hashes: " "pentnote creds sync-pot ~/.hashcat/hashcat.potfile"
    )


def _write_or_echo(lines: list[str], output_path: Path | None) -> None:
    if output_path:
        output_path.write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
        console.print(f"[✓] wrote: {output_path}")
        return
    for line in lines:
        click.echo(line)

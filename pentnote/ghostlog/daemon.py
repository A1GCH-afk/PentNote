"""Async Ghost Log daemon for shell-history intelligence capture."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import click
from pydantic import BaseModel, Field, field_validator

from pentnote.ai.ollama import OllamaError
from pentnote.core.engagement import Engagement, load_local_config
from pentnote.core.fileio import atomic_write_json
from pentnote.core.models import GhostLogSession
from pentnote.ghostlog.apply import apply_extraction
from pentnote.ghostlog.llm import GhostLogExtraction, extract_findings
from pentnote.ghostlog.sanitize import sanitize_terminal_text
from pentnote.workspace.store import WorkspaceStore, append_timeline_entry, now_iso

INTERESTING_COMMANDS = frozenset(
    {
        # Network
        "nmap",
        "masscan",
        "rustscan",
        # AD / SMB
        "crackmapexec",
        "cme",
        "netexec",
        "nxc",
        "impacket-secretsdump",
        "secretsdump",
        "impacket-psexec",
        "psexec",
        "impacket-wmiexec",
        "wmiexec",
        "impacket-smbexec",
        "smbexec",
        "impacket-atexec",
        "atexec",
        "impacket-dcomexec",
        "dcomexec",
        "evil-winrm",
        "ldapsearch",
        "ldapdomaindump",
        "rpcclient",
        "enum4linux",
        "enum4linux-ng",
        # Kerberos
        "kerbrute",
        "rubeus",
        "getTGT.py",
        "getST.py",
        "getUserSPNs.py",
        "getNPUsers.py",
        # AD CS
        "certipy",
        "certipy-ad",
        # BloodHound
        "bloodhound-python",
        "sharphound",
        # Credentials
        "mimikatz",
        "hashcat",
        "john",
        "hydra",
        "medusa",
        "sprayhound",
        # Web
        "gobuster",
        "feroxbuster",
        "ffuf",
        "nikto",
        "nuclei",
        "sqlmap",
        "wfuzz",
        "dirsearch",
        # Post-exploitation
        "msfconsole",
        "msfvenom",
        "chisel",
        "ligolo",
        # C2
        "sliver-client",
        "havoc",
    }
)
IGNORE_COMMANDS = frozenset(
    {
        "ls",
        "ll",
        "la",
        "l",
        "dir",
        "cd",
        "pwd",
        "echo",
        "cat",
        "grep",
        "find",
        "which",
        "whereis",
        "man",
        "help",
        "--help",
        "-h",
        "clear",
        "reset",
        "exit",
        "logout",
        "history",
        "alias",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "touch",
        "chmod",
        "chown",
        "chgrp",
        "ps",
        "top",
        "htop",
        "kill",
        "ping",
        "ifconfig",
        "ip",
        "netstat",
        "ss",
        "python3",
        "python",
        "pip3",
        "pip",
        "git",
        "vim",
        "nano",
        "code",
        "sudo",
        "su",
    }
)
NOISE_COMMANDS = IGNORE_COMMANDS
_INTERESTING_COMMANDS_NORMALIZED = {
    command.casefold() for command in INTERESTING_COMMANDS
}
SECRET_ARGUMENT_RE = re.compile(
    r"(?i)(--?p(?:ass(?:word)?)?|--hash(?:es)?|--ntds|--api[-_]?key|--token|--key)"
    r"(\s+|=)(\"[^\"]+\"|'[^']+'|\S+)"
)
ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|authorization)" r"=([^\s'\"`]+)"
)
BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}")
NTLM_PAIR_RE = re.compile(r"(?i)\b[a-f0-9]{32}:[a-f0-9]{32}\b")
LONG_HEX_SECRET_RE = re.compile(r"(?i)\b[a-f0-9]{64,}\b")
ZSH_EXTENDED_HISTORY_RE = re.compile(r"^: \d+:\d+;(.*)$")


class GhostLogConfig(BaseModel):
    """Runtime settings for the shell-history daemon."""

    history_path: Path
    model: str = "llama3"
    poll_interval: float = Field(default=1.0, gt=0)
    once: bool = False

    @field_validator("history_path")
    @classmethod
    def expand_history_path(cls, value: Path) -> Path:
        return value.expanduser()


class HistoryCommand(BaseModel):
    """A normalized shell history command."""

    command: str = Field(min_length=1)
    sanitized: str = Field(min_length=1)
    interesting: bool


class GhostLogRunResult(BaseModel):
    """Summary for one daemon run."""

    processed: int = 0
    ignored: int = 0
    extracted_credentials: int = 0
    extracted_findings: int = 0
    extracted_log_entries: int = 0
    duplicate_findings: int = 0


def start_daemon(engagement: Engagement) -> Path:
    """Record requested Ghost Log start state."""

    started_at = _now()
    state_path = _state_path(engagement)
    atomic_write_json(
        state_path,
        {
            "running": True,
            "started_at": started_at.isoformat(),
            "pid": os.getpid(),
            "transcript": str(engagement.state_dir / "ghostlog-session.jsonl"),
        },
    )
    session = _load_session(engagement) or GhostLogSession(started_at=started_at)
    session.started_at = started_at
    session.stopped_at = None
    session.commands_seen = 0
    session.commands_kept = 0
    session.credentials_found = 0
    session.findings_found = 0
    session.log_entries_found = 0
    session.last_command = None
    session.last_command_at = None
    _save_session(engagement, session)
    return state_path


def stop_daemon(engagement: Engagement) -> Path:
    """Mark Ghost Log as stopped."""

    state = _load_state(engagement)
    state["running"] = False
    state["stopped_at"] = _timestamp()
    path = _state_path(engagement)
    atomic_write_json(path, state)
    session = _load_session(engagement)
    if session is not None:
        _save_session(engagement, _stop_session(session))
    return path


def status_daemon(engagement: Engagement) -> dict:
    """Return Ghost Log lifecycle state."""

    session = _load_session(engagement)
    state = _load_state(engagement)
    if session is not None:
        state["session"] = session.model_dump(mode="json")
    return state


async def run_history_daemon(
    engagement: Engagement,
    *,
    history_path: Path | None = None,
    model: str | None = None,
    poll_interval: float = 1.0,
    once: bool = False,
    quiet: bool = False,
) -> GhostLogRunResult:
    """Monitor shell history and apply local Ollama intelligence extraction."""

    local_config = load_local_config(engagement)
    config = GhostLogConfig(
        history_path=history_path or _default_history_path(),
        model=model or str(local_config.get("ollama_model") or "llama3"),
        poll_interval=poll_interval,
        once=once,
    )
    start_daemon(engagement)
    stop_event = asyncio.Event()
    _install_signal_handlers(stop_event)
    try:
        return await _monitor_history(engagement, config, stop_event, quiet=quiet)
    finally:
        stop_daemon(engagement)


async def process_history_lines(
    engagement: Engagement,
    lines: Iterable[str],
    *,
    model: str = "llama3",
    quiet: bool = False,
) -> GhostLogRunResult:
    """Process supplied shell-history lines once."""

    result = GhostLogRunResult()
    for line in lines:
        _increment_session(engagement, commands_seen=1)
        command = normalize_history_line(line)
        if command is None or not command.interesting:
            result.ignored += 1
            continue
        _increment_session(
            engagement,
            commands_kept=1,
            last_command=command.sanitized,
        )
        extraction_counts, duplicates = await _handle_command(
            engagement,
            command,
            model=model,
            quiet=quiet,
        )
        result.processed += 1
        result.extracted_credentials += extraction_counts["credentials"]
        result.extracted_findings += extraction_counts["findings"]
        result.extracted_log_entries += extraction_counts["log_entries"]
        result.duplicate_findings += duplicates
    return result


def normalize_history_line(line: str) -> HistoryCommand | None:
    """Normalize zsh/bash history lines and classify operator relevance."""

    command = line.strip()
    if not command:
        return None
    if match := ZSH_EXTENDED_HISTORY_RE.match(command):
        command = match.group(1).strip()
    command = sanitize_terminal_text(command)
    if not command:
        return None
    redacted = redact_command_secrets(command)
    return HistoryCommand(
        command=command,
        sanitized=redacted,
        interesting=is_interesting_command(redacted),
    )


def is_interesting_command(command: str) -> bool:
    """Return whether a command is useful enough for Ghost Log automation."""

    first = _effective_command_name(command)
    if first in IGNORE_COMMANDS:
        return False
    return first in _INTERESTING_COMMANDS_NORMALIZED


def _effective_command_name(command: str) -> str:
    """Return the tool name Ghost Log should classify for a shell command."""

    parts = command.split()
    if not parts:
        return ""
    first = parts[0].split("/")[-1].casefold()
    if first == "pentnote" and len(parts) >= 3 and parts[1] == "run":
        return parts[2].split("/")[-1].casefold()
    return first


def redact_command_secrets(command: str) -> str:
    """Redact obvious inline secrets before they are logged or parsed."""

    command = SECRET_ARGUMENT_RE.sub(r"\1\2<redacted>", command)
    command = ASSIGNMENT_SECRET_RE.sub(r"\1=<redacted>", command)
    command = BEARER_TOKEN_RE.sub("Bearer <redacted>", command)
    command = NTLM_PAIR_RE.sub("<redacted-ntlm-pair>", command)
    return LONG_HEX_SECRET_RE.sub("<redacted-hex-secret>", command)


async def _monitor_history(
    engagement: Engagement,
    config: GhostLogConfig,
    stop_event: asyncio.Event,
    *,
    quiet: bool,
) -> GhostLogRunResult:
    config.history_path.parent.mkdir(parents=True, exist_ok=True)
    config.history_path.touch(exist_ok=True)
    offset = config.history_path.stat().st_size
    aggregate = GhostLogRunResult()

    while not stop_event.is_set():
        lines, offset = _read_new_lines(config.history_path, offset)
        if lines:
            result = await process_history_lines(
                engagement,
                lines,
                model=config.model,
                quiet=quiet,
            )
            aggregate.processed += result.processed
            aggregate.ignored += result.ignored
            aggregate.extracted_credentials += result.extracted_credentials
            aggregate.extracted_findings += result.extracted_findings
            aggregate.extracted_log_entries += result.extracted_log_entries
            aggregate.duplicate_findings += result.duplicate_findings
        if config.once:
            break
        await asyncio.sleep(config.poll_interval)
    return aggregate


def _read_new_lines(path: Path, offset: int) -> tuple[list[str], int]:
    current_size = path.stat().st_size
    if current_size < offset:
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        lines = handle.readlines()
        return lines, handle.tell()


async def _handle_command(
    engagement: Engagement,
    command: HistoryCommand,
    *,
    model: str,
    quiet: bool,
) -> tuple[dict[str, int], int]:
    store = WorkspaceStore(engagement.root)
    entry = {
        "message": f"Ghost Log observed: {command.sanitized}",
        "date": now_iso(),
        "source": "ghostlog",
        "host": _extract_host(command.sanitized),
        "tags": ["ghostlog", "command"],
    }
    store.add_log(entry)
    append_timeline_entry(engagement.notes_dir, entry)

    try:
        extraction = await asyncio.to_thread(
            extract_findings,
            command.sanitized,
            model=model,
        )
    except OllamaError:
        return {"credentials": 0, "findings": 0, "log_entries": 0}, 0
    if not quiet:
        _print_extraction_summary(extraction, command.sanitized)
    new_findings, duplicates = apply_extraction(
        engagement,
        extraction,
        source_command=command.sanitized,
        quiet=quiet,
    )
    counts = _extraction_counts(extraction, new_findings)
    _increment_session(
        engagement,
        credentials_found=counts["credentials"],
        findings_found=counts["findings"],
        log_entries_found=counts["log_entries"],
    )
    return counts, duplicates


def _print_extraction_summary(
    extracted: GhostLogExtraction,
    source_command: str,
) -> None:
    if not any(
        [
            extracted.credentials,
            extracted.findings,
            extracted.notes,
            extracted.log_entries,
        ]
    ):
        return

    items = []
    if extracted.credentials:
        items.append(f"{len(extracted.credentials)} credential(s)")
    if extracted.findings:
        items.append(f"{len(extracted.findings)} finding(s)")
    log_count = len(extracted.notes) + len(extracted.log_entries)
    if log_count:
        items.append(f"{log_count} log entr(ies)")

    click.echo(f"[ghost] {source_command[:60]!r} → " + ", ".join(items))


def _extraction_counts(
    extraction: GhostLogExtraction,
    new_findings: int,
) -> dict[str, int]:
    return {
        "credentials": len(extraction.credentials),
        "findings": new_findings,
        "log_entries": len(extraction.notes) + len(extraction.log_entries),
    }


def _extract_host(command: str) -> str | None:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", command)
    return match.group(0) if match else None


def _default_history_path() -> Path:
    if value := os.environ.get("HISTFILE"):
        return Path(value)
    shell = Path(os.environ.get("SHELL", "")).name
    if shell == "bash":
        return Path("~/.bash_history")
    return Path("~/.zsh_history")


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    try:
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(signum, stop_event.set)
    except (NotImplementedError, RuntimeError):
        return


def _state_path(engagement: Engagement) -> Path:
    engagement.state_dir.mkdir(parents=True, exist_ok=True)
    return engagement.state_dir / "ghostlog-state.json"


def _session_path(engagement: Engagement) -> Path:
    engagement.state_dir.mkdir(parents=True, exist_ok=True)
    return engagement.state_dir / "ghostlog_session.json"


def _load_state(engagement: Engagement) -> dict:
    path = _state_path(engagement)
    if not path.exists():
        return {"running": False}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"running": False, "error": "state file was invalid JSON"}


def _load_session(engagement: Engagement) -> GhostLogSession | None:
    path = _session_path(engagement)
    if not path.exists():
        return None
    try:
        return GhostLogSession.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def _save_session(engagement: Engagement, session: GhostLogSession) -> None:
    atomic_write_json(_session_path(engagement), session.model_dump(mode="json"))


def _increment_session(
    engagement: Engagement,
    *,
    commands_seen: int = 0,
    commands_kept: int = 0,
    credentials_found: int = 0,
    findings_found: int = 0,
    log_entries_found: int = 0,
    last_command: str | None = None,
) -> GhostLogSession:
    session = _load_session(engagement) or GhostLogSession(started_at=_now())
    session.commands_seen += commands_seen
    session.commands_kept += commands_kept
    session.credentials_found += credentials_found
    session.findings_found += findings_found
    session.log_entries_found += log_entries_found
    if last_command is not None:
        session.last_command = last_command
        session.last_command_at = _now()
    _save_session(engagement, session)
    return session


def _stop_session(session: GhostLogSession) -> GhostLogSession:
    """Finalize one Ghost Log session and roll counters into cumulative totals."""

    stopped_at = _now()
    session.stopped_at = stopped_at
    session.total_sessions += 1
    session.cumulative_commands_seen += session.commands_seen
    session.cumulative_commands_kept += session.commands_kept
    session.cumulative_credentials += session.credentials_found
    session.cumulative_findings += session.findings_found
    session.cumulative_log_entries += session.log_entries_found
    session.session_history.append(
        {
            "started": session.started_at.isoformat(),
            "stopped": stopped_at.isoformat(),
            "credentials": session.credentials_found,
            "findings": session.findings_found,
            "commands": session.commands_kept,
            "commands_seen": session.commands_seen,
            "log_entries": session.log_entries_found,
        }
    )
    session.commands_seen = 0
    session.commands_kept = 0
    session.credentials_found = 0
    session.findings_found = 0
    session.log_entries_found = 0
    return session


def _timestamp() -> str:
    return _now().isoformat()


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)

"""Run external pentest tools, save raw output, and parse it."""

from __future__ import annotations

import shlex
import subprocess
import sys
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pentnote.core.engagement import Engagement
from pentnote.core.engine import ParseOutcome, parse_content
from pentnote.core.fileio import atomic_write_text
from pentnote.core.terminal import strip_interactive_noise

TOOL_CONFIG: dict[str, dict[str, Any]] = {
    "nmap": {
        "parser": "nmap",
        "raw_ext": ".xml",
        "raw_subdir": "nmap",
        "xml_flag": True,
    },
    "gobuster": {
        "parser": "gobuster",
        "raw_ext": ".txt",
        "raw_subdir": "gobuster",
        "xml_flag": False,
    },
    "feroxbuster": {
        "parser": "feroxbuster",
        "raw_ext": ".txt",
        "raw_subdir": "feroxbuster",
        "xml_flag": False,
    },
    "cme": {
        "parser": "cme",
        "raw_ext": ".txt",
        "raw_subdir": "cme",
        "xml_flag": False,
    },
    "crackmapexec": {
        "parser": "cme",
        "raw_ext": ".txt",
        "raw_subdir": "cme",
        "xml_flag": False,
    },
    "netexec": {
        "parser": "cme",
        "raw_ext": ".txt",
        "raw_subdir": "cme",
        "xml_flag": False,
    },
    "nxc": {
        "parser": "cme",
        "raw_ext": ".txt",
        "raw_subdir": "cme",
        "xml_flag": False,
    },
    "kerbrute": {
        "parser": "kerbrute",
        "raw_ext": ".txt",
        "raw_subdir": "kerbrute",
        "xml_flag": False,
    },
    "nikto": {
        "parser": "nikto",
        "raw_ext": ".txt",
        "raw_subdir": "nikto",
        "xml_flag": False,
    },
    "nuclei": {
        "parser": "nuclei",
        "raw_ext": ".txt",
        "raw_subdir": "nuclei",
        "xml_flag": False,
    },
    "sqlmap": {
        "parser": "sqlmap",
        "raw_ext": ".txt",
        "raw_subdir": "sqlmap",
        "xml_flag": False,
    },
    "responder": {
        "parser": "responder",
        "raw_ext": ".log",
        "raw_subdir": "responder",
        "xml_flag": False,
    },
    "secretsdump.py": {
        "parser": "impacket-secretsdump",
        "raw_ext": ".txt",
        "raw_subdir": "impacket",
        "xml_flag": False,
    },
    "impacket-secretsdump": {
        "parser": "impacket-secretsdump",
        "raw_ext": ".txt",
        "raw_subdir": "impacket",
        "xml_flag": False,
    },
    "winpeas": {
        "parser": "winpeas",
        "raw_ext": ".txt",
        "raw_subdir": "peas",
        "xml_flag": False,
    },
    "linpeas": {
        "parser": "linpeas",
        "raw_ext": ".txt",
        "raw_subdir": "peas",
        "xml_flag": False,
    },
    "enum4linux": {
        "parser": "enum4linux",
        "raw_ext": ".txt",
        "raw_subdir": "enum4linux",
        "xml_flag": False,
    },
    "enum4linux-ng": {
        "parser": "enum4linux",
        "raw_ext": ".txt",
        "raw_subdir": "enum4linux",
        "xml_flag": False,
    },
    "ffuf": {
        "parser": "gobuster",
        "raw_ext": ".txt",
        "raw_subdir": "ffuf",
        "xml_flag": False,
    },
    "evil-winrm": {
        "parser": "evil-winrm",
        "raw_ext": ".txt",
        "raw_subdir": "evil-winrm",
        "xml_flag": False,
        # Interactive line-editor shells echo keystrokes back as ANSI redraw
        # noise; strip it from the persisted raw file. Scoped to this capture
        # path only -- TTY-adaptive tools (feroxbuster/gobuster) must not.
        "interactive": True,
    },
    "powerview": {
        "parser": "powerview",
        "raw_ext": ".txt",
        "raw_subdir": "powerview",
        "xml_flag": False,
    },
    "seatbelt": {
        "parser": "seatbelt",
        "raw_ext": ".txt",
        "raw_subdir": "seatbelt",
        "xml_flag": False,
    },
    "lazagne": {
        "parser": "lazagne",
        "raw_ext": ".txt",
        "raw_subdir": "lazagne",
        "xml_flag": False,
    },
}

TARGET_FLAGS = {
    "gobuster": ["-u"],
    "feroxbuster": ["-u"],
    "ffuf": ["-u"],
    "nikto": ["-h"],
    "nuclei": ["-u", "-t"],
    "sqlmap": ["-u"],
    "evil-winrm": ["-i"],
}
VALUE_FLAGS = {
    "-h",
    "-i",
    "-l",
    "-oA",
    "-oG",
    "-oN",
    "-oX",
    "-p",
    "-P",
    "-t",
    "-u",
    "-w",
    "--dc",
    "--domain",
}


@dataclass
class RunResult:
    tool: str
    raw_path: Path
    parser: str
    outcome: ParseOutcome
    returncode: int
    terminal_path: Path | None = None


@dataclass
class RawRunResult:
    tool: str
    raw_path: Path
    returncode: int
    terminal_path: Path | None = None


def run_tool(
    tool: str,
    tool_args: list[str],
    vault_root: Path,
    parser_override: str | None = None,
    engagement: Engagement | None = None,
    quiet: bool = False,
) -> RunResult:
    """Run a tool, save raw output, then parse the captured output."""

    normalized_tool = _normalize_tool(tool)
    config = _tool_config(normalized_tool)
    target = _extract_target(normalized_tool, tool_args)
    raw_path = _make_raw_path(vault_root, normalized_tool, config, target)
    if normalized_tool == "nmap":
        output, returncode, parse_content_value, terminal_path = (
            _run_nmap_and_capture_xml(tool, tool_args, raw_path, quiet=quiet)
        )
    else:
        prepared_args = _prepare_args(normalized_tool, tool_args, config)
        output, returncode = _run_and_capture([tool, *prepared_args], quiet=quiet)
        _write_raw_text(
            raw_path,
            output,
            [tool, *tool_args],
            interactive=bool(config.get("interactive")),
        )
        parse_content_value = output
        terminal_path = None

    parser = parser_override or str(config["parser"])
    outcome = parse_content(
        parse_content_value,
        vault_root / "notes",
        tool_name=parser,
        engagement=engagement,
    )
    if (
        engagement is not None
        and parser_override is None
        and normalized_tool not in TOOL_CONFIG
    ):
        _record_unsupported_tool_run(
            engagement, normalized_tool, tool_args, target, outcome.result.hosts
        )
    return RunResult(
        tool=normalized_tool,
        raw_path=raw_path,
        parser=parser,
        outcome=outcome,
        returncode=returncode,
        terminal_path=terminal_path,
    )


def run_raw_only(
    tool: str,
    tool_args: list[str],
    vault_root: Path,
    *,
    quiet: bool = False,
) -> RawRunResult:
    """Run a tool and save raw output without parsing."""

    normalized_tool = _normalize_tool(tool)
    config = _tool_config(normalized_tool)
    target = _extract_target(normalized_tool, tool_args)
    raw_path = _make_raw_path(vault_root, normalized_tool, config, target)
    if normalized_tool == "nmap":
        _output, returncode, _parse_content, terminal_path = _run_nmap_and_capture_xml(
            tool, tool_args, raw_path, quiet=quiet
        )
    else:
        prepared_args = _prepare_args(normalized_tool, tool_args, config)
        output, returncode = _run_and_capture([tool, *prepared_args], quiet=quiet)
        _write_raw_text(
            raw_path,
            output,
            [tool, *tool_args],
            interactive=bool(config.get("interactive")),
        )
        terminal_path = None
    return RawRunResult(
        tool=normalized_tool,
        raw_path=raw_path,
        returncode=returncode,
        terminal_path=terminal_path,
    )


def _tool_config(tool: str) -> dict[str, Any]:
    return TOOL_CONFIG.get(
        tool,
        {
            "parser": "universal",
            "raw_ext": ".txt",
            "raw_subdir": tool,
            "xml_flag": False,
        },
    )


def has_tool_config(tool: str) -> bool:
    return _normalize_tool(tool) in TOOL_CONFIG


def _prepare_args(tool: str, args: list[str], config: dict[str, Any]) -> list[str]:
    if config.get("xml_flag"):
        return _inject_nmap_xml(args)
    return list(args)


def _normalize_tool(tool: str) -> str:
    return Path(tool).name


def _extract_target(tool: str, args: list[str]) -> str:
    """Extract primary target from tool arguments for the raw filename."""

    for flag in TARGET_FLAGS.get(tool, []):
        if flag in args:
            index = args.index(flag)
            if index + 1 < len(args):
                return _clean_target(args[index + 1])

    positionals = _positional_args(args)
    if tool in {"cme", "crackmapexec", "netexec", "nxc"} and len(positionals) >= 2:
        return _clean_target(positionals[1])
    if tool == "kerbrute" and len(positionals) >= 2:
        return _clean_target(positionals[-1])
    if positionals:
        return _clean_target(positionals[-1] if tool == "nmap" else positionals[0])
    return "target"


def _positional_args(args: list[str]) -> list[str]:
    positionals: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in VALUE_FLAGS:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        positionals.append(arg)
    return positionals


def _clean_target(value: str) -> str:
    cleaned = (
        value.replace("http://", "")
        .replace("https://", "")
        .replace("/", "-")
        .replace(":", "-")
        .strip("-")
    )
    return cleaned or "target"


def _make_raw_path(
    vault_root: Path,
    tool: str,
    config: dict[str, Any],
    target: str,
) -> Path:
    """Build raw/{subdir}/{timestamp}-{target}{ext}."""

    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    subdir = vault_root / "raw" / str(config["raw_subdir"])
    subdir.mkdir(parents=True, exist_ok=True)
    filename = f"{timestamp}-{_clean_target(target)}{config['raw_ext']}"
    return subdir / filename


def _inject_nmap_xml(args: list[str]) -> list[str]:
    """Inject -oX - when nmap args do not already specify XML output."""

    if "-oX" in args:
        return list(args)
    return [*args, "-oX", "-"]


def _nmap_args_for_raw_xml(args: list[str], raw_path: Path) -> list[str]:
    """Return nmap args that write XML to raw_path without hiding normal output."""

    prepared = list(args)
    if "-oX" not in prepared:
        return [*prepared, "-oX", str(raw_path)]
    index = prepared.index("-oX")
    if index + 1 < len(prepared):
        prepared[index + 1] = str(raw_path)
    else:
        prepared.append(str(raw_path))
    return prepared


def _run_nmap_and_capture_xml(
    tool: str,
    tool_args: list[str],
    raw_path: Path,
    *,
    quiet: bool = False,
) -> tuple[str, int, str, Path]:
    command = [tool, *_nmap_args_for_raw_xml(tool_args, raw_path)]
    output, returncode = _run_and_capture(command, quiet=quiet)
    terminal_path = raw_path.with_suffix(".txt")
    # Header goes on the human-readable .txt companion only; the .xml raw file
    # is re-read for parsing and must stay valid XML.
    _write_raw_text(terminal_path, output, [tool, *tool_args])
    parse_content_value = (
        raw_path.read_text(encoding="utf-8", errors="replace")
        if raw_path.exists()
        else output
    )
    if not raw_path.exists():
        atomic_write_text(raw_path, output, errors="replace")
    return output, returncode, parse_content_value, terminal_path


def _record_unsupported_tool_run(
    engagement: Engagement,
    tool: str,
    tool_args: list[str],
    target: str,
    hosts: list[Any],
) -> None:
    """Note an unsupported tool run against its host so it is not lost.

    Prefers the explicit run target; falls back to any host the universal
    parser recovered from the output. Host-less wrapper tools (no host-like
    target and no discovered IP) are intentionally skipped -- there is no host
    note to attach the record to.
    """

    from pentnote.workspace.store import record_unsupported_tool, target_type

    if target_type(target) == "host":
        host_ids = [target]
    else:
        host_ids = [host.ip for host in hosts if getattr(host, "ip", "")]
    command = shlex.join([tool, *tool_args])
    for host in dict.fromkeys(host_ids):
        record_unsupported_tool(engagement.notes_dir, host, tool, command)


def _write_raw_text(
    path: Path,
    output: str,
    command: list[str],
    *,
    interactive: bool = False,
) -> None:
    """Persist captured tool output to a raw text file.

    Records the exact invocation as a ``# Command:`` header so the file is
    self-documenting on later review. For interactive-shell captures the
    ANSI/redraw noise is collapsed first; all other tools are written verbatim
    to preserve their (possibly TTY-adaptive) output byte-for-byte after the
    header line.
    """

    body = strip_interactive_noise(output) if interactive else output
    header = f"# Command: {shlex.join(command)}\n"
    atomic_write_text(path, header + body, errors="replace")


def _run_and_capture(command: list[str], *, quiet: bool = False) -> tuple[str, int]:
    output_chunks: list[bytes] = []
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    try:
        if proc.stdout is not None:
            while chunk := proc.stdout.read(4096):
                output_chunks.append(chunk)
                if not quiet:
                    sys.stdout.write(_decode_output_chunk(chunk))
                    sys.stdout.flush()
        returncode = proc.wait()
    except KeyboardInterrupt:
        returncode = _interrupt_process(proc)
    return _decode_output_chunk(b"".join(output_chunks)), returncode


def _decode_output_chunk(chunk: bytes) -> str:
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        return chunk.decode("latin-1", errors="replace")


def _interrupt_process(proc: subprocess.Popen) -> int:
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        with suppress(Exception):
            proc.kill()
    return 130

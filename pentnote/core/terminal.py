"""Render interactive-shell capture into readable plain text.

Interactive tools such as Evil-WinRM drive a line editor (Ruby's Reline)
that echoes keystrokes back through the captured stdout stream using ANSI
cursor movement. A single typed command therefore lands in the raw capture
as a character-by-character redraw (``u`` -> ``up`` -> ``upl`` ... ``upload``)
interleaved with colour codes, cursor show/hide, and column-jump sequences.

This module replays those control sequences against a small line buffer so the
persisted raw file shows the final rendered text (prompt + full command +
output) instead of the redraw noise, while leaving ordinary program output
untouched. It is deliberately scoped to the interactive-shell capture path --
TTY-adaptive tools (feroxbuster, gobuster) must keep their byte-for-byte
capture and never pass through here.
"""

from __future__ import annotations

import re

# CSI: ESC [ , optional private '?', numeric/';' params, optional intermediates,
# final byte. Covers colour (m), cursor moves (G/C/D/H), erase (K/J), and the
# cursor show/hide toggles (?25l / ?25h).
_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# OSC: ESC ] ... terminated by BEL or ST (ESC \). Used for window titles.
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
# Readline bracket markers for "non-printing" prompt regions (\001 / \002).
_PROMPT_MARKERS = ("\x01", "\x02")


def strip_interactive_noise(text: str) -> str:
    """Collapse ANSI/redraw noise from an interactive-shell capture.

    Args:
        text: Raw captured stdout from an interactive shell session.

    Returns:
        Plain text with colour codes, cursor movement, and partial-line
        redraw sequences resolved to their final on-screen result. Trailing
        whitespace per line is stripped; a trailing newline is preserved when
        present in the input.
    """

    for marker in _PROMPT_MARKERS:
        text = text.replace(marker, "")
    text = _OSC_RE.sub("", text)

    lines: list[str] = []
    line: list[str] = []
    col = 0
    index = 0
    length = len(text)

    while index < length:
        char = text[index]

        if char == "\x1b":
            match = _CSI_RE.match(text, index)
            if not match:
                # Lone ESC or an escape we do not model: drop the ESC byte.
                index += 1
                continue
            col, line = _apply_csi(match.group(0), col, line)
            index = match.end()
            continue

        if char == "\n":
            lines.append("".join(line).rstrip())
            line = []
            col = 0
            index += 1
            continue

        if char == "\r":
            col = 0
            index += 1
            continue

        if char == "\b":
            col = max(0, col - 1)
            index += 1
            continue

        if char == "\t":
            char = " "

        if ord(char) < 0x20:
            # Drop remaining non-printing control bytes.
            index += 1
            continue

        while len(line) <= col:
            line.append(" ")
        line[col] = char
        col += 1
        index += 1

    if line:
        lines.append("".join(line).rstrip())

    rendered = "\n".join(lines)
    if text.endswith("\n"):
        rendered += "\n"
    return rendered


def _apply_csi(seq: str, col: int, line: list[str]) -> tuple[int, list[str]]:
    """Apply one CSI sequence to the cursor column and current line buffer."""

    final = seq[-1]
    params = seq[2:-1].lstrip("?")

    if final == "G":  # CHA - cursor to absolute column (1-based)
        col = max(0, _first_param(params, default=1) - 1)
    elif final == "C":  # cursor forward
        col += _first_param(params, default=1)
    elif final == "D":  # cursor back
        col = max(0, col - _first_param(params, default=1))
    elif final == "K":  # EL - erase in line
        mode = _first_param(params, default=0)
        if mode == 0:
            del line[col:]
        elif mode == 1:
            for position in range(min(col + 1, len(line))):
                line[position] = " "
        elif mode == 2:
            line.clear()
    # SGR (m), cursor show/hide (h/l), and any other movement/erase we do not
    # model are simply dropped -- they carry no printable content.
    return col, line


def _first_param(params: str, *, default: int) -> int:
    field = params.split(";")[0]
    if not field.isdigit():
        return default
    return int(field)

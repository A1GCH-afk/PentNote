"""Sanitize terminal logs before LLM extraction."""

from __future__ import annotations

import re

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
PROMPT_RE = re.compile(
    r"(?m)^(?:\([^)]*\)\s*)?(?:[\w.-]+@[\w.-]+:[^\n]*[$#]|[➜❯]\s+[^\n]*)\s*"
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_terminal_text(value: str) -> str:
    """Strip ANSI escapes, prompts, and terminal control artifacts."""

    value = OSC_RE.sub("", value)
    value = ANSI_RE.sub("", value)
    value = CONTROL_RE.sub("", value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = PROMPT_RE.sub("", value)
    lines = [line.rstrip() for line in value.splitlines()]
    return "\n".join(line for line in lines if line.strip()).strip()

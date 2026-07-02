"""Gobuster parser."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from pyparsing import ParseException, Suppress, Word, nums, printables, restOfLine

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_GOBUSTER_LINE = (
    Word(printables)("path")
    + Suppress("(Status:")
    + Word(nums)("status")
    + Suppress(")")
    + restOfLine("details")
)
_GOBUSTER_VHOST_LINE = re.compile(
    r"^(?P<path>.+?)\s+Status:\s+(?P<status>\d{3})(?P<details>\s+.*)?$"
)


class GobusterParser(AbstractParser):
    """Parse Gobuster directory output."""

    tool_name = "gobuster"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Gobuster output."""

        lines = [line.strip() for line in content.splitlines() if line.strip()]
        parsed = sum(_parse_line(line) is not None for line in lines)
        score = min(0.8, parsed * 0.35)
        if "gobuster" in content.casefold():
            score += 0.3
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Gobuster output into path findings."""

        findings: list[Finding] = []
        partial = False
        target_host = _target_host(content)
        for line in self.clean(content).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parsed = _parse_line(stripped)
            if parsed is None:
                if "(Status:" in stripped or " Status:" in stripped:
                    partial = True
                continue
            path = parsed["path"]
            status = parsed["status"]
            title = (
                f"Web virtual host discovered: {path}"
                if parsed["kind"] == "vhost"
                else f"Web path discovered: {path}"
            )
            findings.append(
                _finding(self.tool_name, title, stripped, status, target_host)
            )
        return ParsedResult(self.tool_name, partial, [], [], findings, [], content)


def _parse_line(line: str) -> dict[str, str] | None:
    try:
        parsed = _GOBUSTER_LINE.parse_string(line, parse_all=True)
        return {
            "path": parsed["path"],
            "status": parsed["status"],
            "kind": "path",
        }
    except ParseException:
        pass
    if parsed := _GOBUSTER_VHOST_LINE.match(line):
        return {
            "path": parsed.group("path").strip(),
            "status": parsed.group("status"),
            "kind": "vhost",
        }
    return None


def _finding(
    tool: str,
    title: str,
    evidence: str,
    status: str,
    host: str | None,
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.LOW if status.startswith(("2", "3")) else Severity.INFO,
        mitre_matches=[],
        affected_hosts=[host] if host else [],
        evidence=evidence,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, host or "", title),
    )


def _target_host(content: str) -> str | None:
    for line in content.splitlines():
        if "url:" in line.casefold():
            candidate = line.split(":", 1)[1].strip()
            host = urlparse(candidate).hostname
            if host:
                return host
        for token in line.split():
            host = urlparse(token).hostname
            if host:
                return host
    return None

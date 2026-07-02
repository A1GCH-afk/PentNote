"""Feroxbuster parser."""

from __future__ import annotations

from urllib.parse import urlparse

from pyparsing import ParseException, Word, alphas, nums, printables

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_FEROX_LINE = (
    Word(nums, min=3, max=3)("status")
    + Word(alphas)("method")
    + Word(printables)("lines")
    + Word(printables)("words")
    + Word(printables)("chars")
    + Word(printables)("url")
)


class FeroxbusterParser(AbstractParser):
    """Parse Feroxbuster output."""

    tool_name = "feroxbuster"
    aliases = ("ferox",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Feroxbuster output."""

        lines = [line.strip() for line in content.splitlines() if line.strip()]
        parsed = sum(_parse_line(line) is not None for line in lines)
        score = min(0.8, parsed * 0.35)
        if "feroxbuster" in content.casefold():
            score += 0.3
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Feroxbuster output into path findings."""

        findings: list[Finding] = []
        partial = False
        for line in self.clean(content).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parsed = _parse_line(stripped)
            if parsed is None:
                if stripped[:3].isdigit():
                    partial = True
                continue
            title = f"Web path discovered: {parsed['url']}"
            host = urlparse(parsed["url"]).hostname
            findings.append(
                _finding(self.tool_name, title, stripped, parsed["status"], host)
            )
        return ParsedResult(self.tool_name, partial, [], [], findings, [], content)


def _parse_line(line: str) -> dict[str, str] | None:
    try:
        parsed = _FEROX_LINE.parse_string(line, parse_all=True)
    except ParseException:
        return None
    return {"status": parsed["status"], "url": parsed["url"]}


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

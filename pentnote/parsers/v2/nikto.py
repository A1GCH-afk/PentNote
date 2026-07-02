"""Nikto parser."""

from __future__ import annotations

from urllib.parse import urlparse

from pyparsing import ParseException, Suppress, Word, printables, restOfLine

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_NIKTO_LINE = Suppress("+") + Word(printables)("subject") + restOfLine("details")


class NiktoParser(AbstractParser):
    """Parse Nikto output."""

    tool_name = "nikto"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Nikto output."""

        lines = [line.strip() for line in content.splitlines() if line.strip()]
        parsed = sum(_parse_line(line) is not None for line in lines)
        score = min(0.8, parsed * 0.3)
        if "nikto" in content.casefold():
            score += 0.35
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Nikto findings."""

        findings: list[Finding] = []
        partial = False
        target_host = _target_host(content)
        for line in self.clean(content).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parsed = _parse_line(stripped)
            if parsed is None:
                if stripped.startswith("+"):
                    partial = True
                continue
            title = f"Nikto finding: {parsed['subject'].rstrip(':')}"
            findings.append(
                Finding(
                    title=title,
                    severity=_severity(stripped),
                    mitre_matches=[],
                    affected_hosts=[target_host] if target_host else [],
                    evidence=stripped,
                    next_steps=[],
                    defenses=[],
                    chain_member=None,
                    hash=finding_hash(self.tool_name, target_host or "", title),
                )
            )
        return ParsedResult(self.tool_name, partial, [], [], findings, [], content)


def _parse_line(line: str) -> dict[str, str] | None:
    try:
        parsed = _NIKTO_LINE.parse_string(line, parse_all=True)
    except ParseException:
        return None
    return {"subject": parsed["subject"], "details": parsed["details"].strip()}


def _severity(line: str) -> Severity:
    lowered = line.casefold()
    if "critical" in lowered:
        return Severity.CRITICAL
    if "vulnerab" in lowered or "outdated" in lowered:
        return Severity.HIGH
    if "cookie" in lowered or "header" in lowered:
        return Severity.MEDIUM
    return Severity.INFO


def _target_host(content: str) -> str | None:
    for line in content.splitlines():
        lowered = line.casefold()
        if "target ip:" in lowered or "target host:" in lowered:
            return line.split(":", 1)[1].strip()
        if "target port:" in lowered:
            continue
        for token in line.split():
            host = urlparse(token).hostname
            if host:
                return host
    return None

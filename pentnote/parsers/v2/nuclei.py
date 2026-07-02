"""Nuclei parser."""

from __future__ import annotations

from pyparsing import ParseException, Suppress, Word, printables

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_NUCLEI_LINE = (
    Suppress("[")
    + Word(printables, exclude_chars="]")("template")
    + Suppress("]")
    + Suppress("[")
    + Word(printables, exclude_chars="]")("severity")
    + Suppress("]")
    + Suppress("[")
    + Word(printables, exclude_chars="]")("protocol")
    + Suppress("]")
    + Word(printables)("target")
)


class NucleiParser(AbstractParser):
    """Parse Nuclei output."""

    tool_name = "nuclei"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Nuclei output."""

        lines = [line.strip() for line in content.splitlines() if line.strip()]
        parsed = sum(_parse_line(line) is not None for line in lines)
        score = min(0.8, parsed * 0.4)
        if "nuclei" in content.casefold():
            score += 0.2
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Nuclei findings."""

        findings: list[Finding] = []
        partial = False
        for line in self.clean(content).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parsed = _parse_line(stripped)
            if parsed is None:
                if stripped.startswith("["):
                    partial = True
                continue
            title = f"Nuclei finding {parsed['template']} on {parsed['target']}"
            findings.append(
                Finding(
                    title=title,
                    severity=_severity(parsed["severity"]),
                    mitre_matches=[],
                    affected_hosts=[parsed["target"]],
                    evidence=stripped,
                    next_steps=[],
                    defenses=[],
                    chain_member=None,
                    hash=finding_hash(self.tool_name, parsed["target"], title),
                )
            )
        return ParsedResult(self.tool_name, partial, [], [], findings, [], content)


def _parse_line(line: str) -> dict[str, str] | None:
    try:
        parsed = _NUCLEI_LINE.parse_string(line, parse_all=True)
    except ParseException:
        return None
    return {
        "template": parsed["template"],
        "severity": parsed["severity"],
        "protocol": parsed["protocol"],
        "target": parsed["target"],
    }


def _severity(value: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(value.casefold(), Severity.INFO)

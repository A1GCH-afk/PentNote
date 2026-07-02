"""sqlmap parser."""

from __future__ import annotations

from pyparsing import CaselessLiteral, ParseException, restOfLine

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_INJECTION_LINE = CaselessLiteral("parameter").suppress() + restOfLine("details")


class SQLMapParser(AbstractParser):
    """Parse sqlmap injection findings."""

    tool_name = "sqlmap"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is sqlmap output."""

        lowered = content.casefold()
        score = 0.0
        if "sqlmap" in lowered:
            score += 0.4
        if (
            "is vulnerable" in lowered
            or "parameter" in lowered
            and "injectable" in lowered
        ):
            score += 0.6
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse sqlmap output into findings."""

        findings: list[Finding] = []
        partial = False
        for line in self.clean(content).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if (
                "injectable" not in stripped.casefold()
                and "is vulnerable" not in stripped.casefold()
            ):
                continue
            try:
                _INJECTION_LINE.parse_string(stripped, parse_all=False)
            except ParseException:
                partial = True
                continue
            title = "SQL injection identified"
            findings.append(
                Finding(
                    title=title,
                    severity=Severity.HIGH,
                    mitre_matches=[],
                    affected_hosts=[],
                    evidence=stripped,
                    next_steps=[],
                    defenses=[],
                    chain_member=None,
                    hash=finding_hash(self.tool_name, "", title),
                )
            )
        return ParsedResult(self.tool_name, partial, [], [], findings, [], content)

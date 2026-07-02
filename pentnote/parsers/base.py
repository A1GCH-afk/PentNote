"""Parser interface and shared parser helpers."""

from __future__ import annotations

import hashlib
import re
import traceback
from abc import ABC, abstractmethod

from pentnote.models import Finding, ParsedResult, Severity


class ParserError(RuntimeError):
    """Raised when a parser cannot recover a valid result."""


class AbstractParser(ABC):
    """Strategy interface implemented by all PentNote parsers."""

    tool_name = "unknown"
    aliases: tuple[str, ...] = ()
    supported_extensions: tuple[str, ...] = ()

    def clean(self, content: str) -> str:
        """Normalize parser input and remove terminal/binary noise.

        Args:
            content: Raw tool output.

        Returns:
            Cleaned tool output with ANSI escapes removed, normalized newlines,
            long lines truncated, and null bytes stripped.
        """

        ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~])")
        cleaned = ansi.sub("", str(content))
        cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
        cleaned = cleaned.replace("\x00", "")
        lines = []
        for line in cleaned.splitlines():
            if len(line) > 2000:
                lines.append(line[:2000] + " [truncated]")
            else:
                lines.append(line)
        return "\n".join(lines).strip()

    def safe_parse(self, content: str) -> ParsedResult:
        """Parse with recovery so malformed input never crashes the caller."""

        cleaned = self.clean(content)
        if not cleaned.strip():
            return self._empty_result("empty input")
        try:
            return self.parse(cleaned)
        except Exception as exc:
            title = f"Parser error: {self.tool_name}"
            evidence = f"Parse failed: {exc}\n" f"{traceback.format_exc()[-500:]}"
            return ParsedResult(
                tool=self.tool_name,
                partial=True,
                hosts=[],
                credentials=[],
                findings=[
                    Finding(
                        title=title,
                        severity=Severity.INFO,
                        mitre_matches=[],
                        affected_hosts=[],
                        evidence=evidence,
                        next_steps=["Check raw file for encoding issues."],
                        defenses=[],
                        chain_member=None,
                        hash=_parser_error_hash(self.tool_name, evidence),
                    )
                ],
                domain_objects=[],
                raw_text=cleaned[:1000],
            )

    def _empty_result(self, reason: str) -> ParsedResult:
        """Return an empty parsed result for non-actionable input."""

        del reason
        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=[],
            domain_objects=[],
            raw_text="",
        )

    @abstractmethod
    def can_parse(self, content: str) -> float:
        """Return a confidence score between 0.0 and 1.0.

        Args:
            content: Raw tool output.

        Returns:
            Confidence that this parser handles the content.
        """

    @abstractmethod
    def parse(self, content: str) -> ParsedResult:
        """Parse raw content into normalized Pydantic model objects.

        Args:
            content: Raw tool output.

        Returns:
            Structured parsed result.
        """


BaseParser = AbstractParser


def _parser_error_hash(tool_name: str, evidence: str) -> str:
    payload = f"{tool_name.casefold()}|parser-error|{evidence[:200]}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

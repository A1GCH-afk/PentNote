"""Havoc C2 console log parser."""

from __future__ import annotations

from pentnote.parsers.c2.generic import (
    HAVOC_SIGNALS,
    GenericC2LogParser,
    framework_signal_confidence,
)


class HavocLogParser(GenericC2LogParser):
    """Parse Havoc console logs with framework-specific fingerprinting."""

    tool_name = "havoc"
    aliases = ("havoc-c2",)
    framework = "havoc"

    def fingerprint(self, content: str) -> float:
        return framework_signal_confidence(content, HAVOC_SIGNALS)

    def can_parse(self, content: str) -> float:
        return self.fingerprint(content)

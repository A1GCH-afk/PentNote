"""Sliver C2 console log parser."""

from __future__ import annotations

from pentnote.parsers.c2.generic import (
    SLIVER_SIGNALS,
    GenericC2LogParser,
    framework_signal_confidence,
)


class SliverLogParser(GenericC2LogParser):
    """Parse Sliver console logs with framework-specific fingerprinting."""

    tool_name = "sliver"
    aliases = ("sliver-c2",)
    framework = "sliver"

    def fingerprint(self, content: str) -> float:
        return framework_signal_confidence(content, SLIVER_SIGNALS)

    def can_parse(self, content: str) -> float:
        return self.fingerprint(content)

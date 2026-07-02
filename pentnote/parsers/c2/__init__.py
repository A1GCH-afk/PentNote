"""C2 console log parser scaffolding."""

from pentnote.parsers.c2.base import (
    C2Credential,
    C2Download,
    C2Parser,
    C2ParseResult,
    C2Session,
)
from pentnote.parsers.c2.generic import GenericC2LogParser
from pentnote.parsers.c2.havoc import HavocLogParser
from pentnote.parsers.c2.registry import (
    C2_PARSERS,
    available_c2_parsers,
    c2_parser_by_name,
    detect_c2_parser,
)
from pentnote.parsers.c2.sliver import SliverLogParser

__all__ = [
    "C2_PARSERS",
    "C2Credential",
    "C2Download",
    "C2ParseResult",
    "C2Parser",
    "C2Session",
    "GenericC2LogParser",
    "HavocLogParser",
    "SliverLogParser",
    "available_c2_parsers",
    "c2_parser_by_name",
    "detect_c2_parser",
]

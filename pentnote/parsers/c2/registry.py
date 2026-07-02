"""Registry for framework-specific C2 parsers."""

from __future__ import annotations

from pentnote.parsers.c2.havoc import HavocLogParser
from pentnote.parsers.c2.sliver import SliverLogParser

C2_PARSERS = (SliverLogParser, HavocLogParser)


def available_c2_parsers() -> list[SliverLogParser | HavocLogParser]:
    """Return all built-in C2 parser instances."""

    return [parser_cls() for parser_cls in C2_PARSERS]


def c2_parser_by_name(name: str) -> SliverLogParser | HavocLogParser:
    """Resolve a C2 parser by exact tool name or alias."""

    requested = name.casefold()
    for parser in available_c2_parsers():
        names = {
            parser.tool_name.casefold(),
            *(alias.casefold() for alias in parser.aliases),
        }
        if requested in names:
            return parser
    raise KeyError(name)


def detect_c2_parser(content: str) -> SliverLogParser | HavocLogParser | None:
    """Detect a framework-specific C2 parser without generic fallbacks."""

    scored = sorted(
        ((parser, parser.fingerprint(content)) for parser in available_c2_parsers()),
        key=lambda item: item[1],
        reverse=True,
    )
    if not scored or scored[0][1] < 0.4:
        return None
    return scored[0][0]

"""Entry-point based plugin loading."""

from __future__ import annotations

from importlib.metadata import entry_points

from pentnote.parsers.base import AbstractParser


def load_parser_plugins() -> list[AbstractParser]:
    """Load community parsers registered under ``pentnote.parsers``."""

    parsers: list[AbstractParser] = []
    discovered = entry_points(group="pentnote.parsers")
    for entry_point in discovered:
        parser_cls = entry_point.load()
        parser = parser_cls()
        if not isinstance(parser, AbstractParser):
            continue
        parsers.append(parser)
    return parsers

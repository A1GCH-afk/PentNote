"""High-level parse orchestration."""

from __future__ import annotations

from pathlib import Path

from pentnote.core.engagement import Engagement, merge_and_save_findings
from pentnote.core.models import PentNoteModel
from pentnote.generators.markdown import write_result_markdown
from pentnote.models import ParsedResult
from pentnote.parsers.detector import detect_parser, parser_by_name


class ParseOutcome(PentNoteModel):
    """Result of parsing and writing one input."""

    result: ParsedResult
    written: list[Path]
    new_findings: int
    duplicate_findings: int


def parse_content(
    content: str,
    output_dir: Path,
    *,
    tool_name: str | None = None,
    engagement: Engagement | None = None,
) -> ParseOutcome:
    """Parse content, write notes, and persist findings when in an engagement."""

    parser = parser_by_name(tool_name) if tool_name else detect_parser(content).parser
    result = parser.safe_parse(content)
    notes_dir = engagement.notes_dir if engagement else output_dir
    written = write_result_markdown(
        result,
        notes_dir,
        engagement_name=engagement.name if engagement else "PentNote",
        target_groups=engagement.target_groups if engagement else None,
    )
    new_count = 0
    duplicate_count = 0
    if engagement and result.findings:
        new, duplicates = merge_and_save_findings(engagement, result.findings)
        new_count = len(new)
        duplicate_count = len(duplicates)
    return ParseOutcome(result, written, new_count, duplicate_count)

"""Obsidian map-of-content generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pentnote.generators.markdown import template_env
from pentnote.models import Finding


def write_index(
    findings: list[Finding],
    output_dir: Path,
    *,
    engagement_name: str,
    scope: list[str] | None = None,
) -> Path:
    """Write the engagement map of content."""

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "00_Index.md"
    template = template_env().get_template("engagement.md.j2")
    techniques = sorted(
        {match.technique_id for finding in findings for match in finding.mitre_matches}
    )
    path.write_text(
        template.render(
            findings=findings,
            techniques=techniques,
            engagement_name=engagement_name,
            scope=scope or [],
            iso_timestamp=_now_iso(),
        ),
        encoding="utf-8",
    )
    return path


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()

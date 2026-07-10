"""Render and inject LotL suggestions into target notes."""

from __future__ import annotations

from pathlib import Path

from pentnote.core.engagement import Engagement
from pentnote.core.fileio import atomic_write_text
from pentnote.core.models import DefenseProfile, PayloadContext
from pentnote.payloads.context import build_contexts
from pentnote.payloads.lotl import generate_lotl_steps
from pentnote.workspace.store import host_note_path

SECTION_PREFIX = "## Payload Guidance"


def refresh_payloads(
    engagement: Engagement,
    *,
    host: str | None = None,
    credential_user: str | None = None,
) -> list[Path]:
    """Generate and inject operator payload suggestions into host notes."""

    written: list[Path] = []
    for context in build_contexts(
        engagement, host=host, credential_user=credential_user
    ):
        note_path = host_note_path(engagement.notes_dir, context.host_ip)
        if not note_path.exists():
            atomic_write_text(note_path, f"# {context.host_ip}\n\n## Notes\n")
        section = render_payload_guidance(context, generate_lotl_steps(context))
        _replace_section(note_path, section)
        written.append(note_path)
    return sorted(set(written))


def render_payload_guidance(
    context: PayloadContext,
    commands: list[str],
    defenses: DefenseProfile | None = None,
) -> str:
    """Render payload guidance Markdown for a host note."""

    target = context.hostname or context.host_ip
    os_name = context.os or "Unknown"
    defenses = defenses or context.defenses
    body = "\n".join(f"```bash\n{command}\n```\n" for command in commands)
    if not body:
        body = "_No target-specific commands matched the currently known open ports._\n"
    defense_context = _render_defense_context(defenses)
    return (
        f"{SECTION_PREFIX} — {target}\n"
        f"**OS:** {os_name}\n"
        f"**Available Credentials:** {len(context.credentials)}\n\n"
        f"{defense_context}"
        "### Commands\n"
        f"{body}"
    )


def _render_defense_context(defenses: DefenseProfile) -> str:
    lines = ["## Defense Context"]
    if defenses.edr_detected:
        lines.extend(
            [
                "> [!warning] EDR Detected",
                f"> {', '.join(defenses.edr_detected)} - use LOTL techniques",
            ]
        )
    if defenses.av_detected:
        lines.extend(
            [
                "> [!caution] AV Detected",
                f"> {', '.join(defenses.av_detected)} - avoid known signatures",
            ]
        )
    if len(lines) == 1:
        lines.append("_No AV/EDR indicators found in current findings._")
    return "\n".join(lines) + "\n\n"


def _replace_section(path: Path, section: str) -> None:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if SECTION_PREFIX not in text:
        atomic_write_text(path, f"{text.rstrip()}\n\n{section.rstrip()}\n")
        return
    before, after = text.split(SECTION_PREFIX, 1)
    split_index = _next_outer_section_index(after)
    if split_index is not None:
        remainder = after[split_index + 1 :]
        new_text = (
            before.rstrip() + "\n\n" + section.rstrip() + "\n\n" + remainder.lstrip()
        )
    else:
        new_text = before.rstrip() + "\n\n" + section.rstrip() + "\n"
    atomic_write_text(path, new_text)


def _next_outer_section_index(markdown: str) -> int | None:
    allowed_inside = {"## Defense Context"}
    offset = 0
    for line in markdown.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("## ") and stripped not in allowed_inside:
            return offset
        offset += len(line)
    return None

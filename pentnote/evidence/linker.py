"""Append visual evidence links to target notes."""

from __future__ import annotations

from pathlib import Path

from pentnote.workspace.store import append_to_note_path, host_note_path, now_iso


def append_evidence_link(
    notes_dir: Path,
    target: str,
    attachment_name: str,
    *,
    ocr_text: str = "",
) -> Path:
    """Append an Obsidian image embed and optional OCR comment to a host note."""

    note_path = host_note_path(notes_dir, target)
    if not note_path.exists():
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(f"# {target}\n\n## Notes\n", encoding="utf-8")
    lines = [f"{now_iso()} - ![[{attachment_name}]]"]
    if ocr_text.strip():
        lines.append(f"<!-- OCR: {_clean_comment(ocr_text)} -->")
    append_to_note_path(note_path, "\n  ".join(lines))
    return note_path


def _clean_comment(value: str) -> str:
    return " ".join(value.replace("--", "-").split())

"""Filesystem write helpers.

State files (host/loot notes and the like) are written by replacing the whole
file. A direct ``open(path, "w")`` truncates the target before the new bytes
land, so an interruption mid-write (crash, kill, disk full) leaves a truncated
or empty note -- silent data loss. Writing to a sibling temp file and then
atomically renaming it over the target avoids that: readers only ever see the
old complete file or the new complete file, never a half-written one.
"""

from __future__ import annotations

from pathlib import Path


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write ``text`` to ``path`` atomically via a same-directory temp file.

    The temp file is created alongside the target (same filesystem, so the
    rename is atomic) and replaced onto it. Any existing file at ``path`` is
    left untouched until the rename succeeds.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{path.name}.tmp"
    tmp_path.write_text(text, encoding=encoding)
    tmp_path.replace(path)

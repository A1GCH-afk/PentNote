"""Filesystem write helpers.

State files (host/loot notes, JSON stores, and the like) are written by
replacing the whole file. A direct ``open(path, "w")`` truncates the target
before the new bytes land, so an interruption mid-write (crash, kill, disk
full, Ctrl-C) leaves a truncated or empty file -- silent data loss. Writing to
a sibling temp file, fsyncing it, and then atomically renaming it over the
target avoids that: readers only ever see the old complete file or the new
complete file, never a half-written one.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4


def atomic_write_text(
    path: Path, text: str, *, encoding: str = "utf-8", errors: str = "strict"
) -> None:
    """Write ``text`` to ``path`` atomically via a same-directory temp file.

    The temp file is created alongside the target (same filesystem, so the
    rename is atomic -- a cross-filesystem rename would silently degrade to
    copy+delete and reintroduce the exact failure mode this guards against).
    Its content is flushed and fsynced before the rename, so the new bytes are
    actually on disk rather than sitting in a buffer. Any existing file at
    ``path`` is left completely untouched until the rename succeeds; if
    anything raises before then, the temp file is removed and the exception
    propagates.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    # Mirror the permissions a plain open(path, "w") would produce (subject to
    # umask) rather than tempfile's more restrictive default -- the original
    # file's mode is copied over explicitly below when one already exists.
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding=encoding, errors=errors) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            shutil.copymode(path, tmp_path)
        os.replace(tmp_path, path)
        replaced = True
    finally:
        if not replaced:
            tmp_path.unlink(missing_ok=True)


def atomic_write_json(path: Path, value: Any, *, indent: int = 2) -> None:
    """Serialize ``value`` as JSON and write it atomically via `atomic_write_text`."""

    atomic_write_text(path, json.dumps(value, indent=indent) + "\n")

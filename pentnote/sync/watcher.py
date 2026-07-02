"""Optional file watcher for collaboration sync."""

from __future__ import annotations

from pathlib import Path

from pentnote.sync.git import sync_once


def watch_and_sync(root: Path, *, remote: str = "origin", branch: str = "") -> None:
    """Watch the vault and sync after file changes."""

    try:
        from watchfiles import watch
    except ImportError as exc:
        raise RuntimeError(
            "Install PentNote with pentnote[operator] to use sync --watch."
        ) from exc

    for _changes in watch(root):
        sync_once(root, remote=remote, branch=branch)

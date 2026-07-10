"""Vault .gitignore helpers for collaboration mode."""

from __future__ import annotations

from pathlib import Path

import click

from pentnote.core.fileio import atomic_write_text
from pentnote.core.init_engine import GITIGNORE_ENTRIES

IGNORE_ENTRIES = [
    *GITIGNORE_ENTRIES,
    ".pentnote/sync-conflicts.json",
    ".pentnote/cache/",
]
REQUIRED_SYNC_IGNORE_ENTRIES = (
    ".pentnote/local.json",
    ".pentnote/workspace.json",
)


def ensure_gitignore(root: Path) -> Path:
    """Ensure operator-local state is ignored."""

    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    known = {line.strip() for line in existing}
    additions = [entry for entry in IGNORE_ENTRIES if entry not in known]
    if additions:
        lines = existing[:]
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("# PentNote operator-local state")
        lines.extend(additions)
        atomic_write_text(path, "\n".join(lines).rstrip() + "\n")
    return path


def missing_required_gitignore_entries(root: Path) -> list[str]:
    """Return required sensitive paths absent from the vault gitignore."""

    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    known = {line.strip() for line in existing}
    return [entry for entry in REQUIRED_SYNC_IGNORE_ENTRIES if entry not in known]


def warn_if_sensitive_paths_not_ignored(root: Path) -> list[str]:
    """Warn before sync when operator-local JSON is not gitignored."""

    missing = missing_required_gitignore_entries(root)
    for entry in missing:
        name = Path(entry).name
        click.echo(
            f"[!] {name} not in .gitignore — run pentnote status --health --fix",
            err=True,
        )
    return missing

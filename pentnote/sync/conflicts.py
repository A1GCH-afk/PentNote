"""Markdown-aware conflict reporting helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def log_conflicts(root: Path, files: list[str]) -> Path:
    """Write unresolved conflict metadata for operator review."""

    path = root / ".pentnote" / "sync-conflicts.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "date": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "files": files,
        "message": "Manual review required for unresolved Git conflicts.",
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path

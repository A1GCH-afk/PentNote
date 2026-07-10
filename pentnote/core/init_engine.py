"""Safe engagement initialization and OPSEC defaults."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pentnote.core.fileio import atomic_write_json, atomic_write_text
from pentnote.core.models import Engagement, EngagementType, TargetGroup

SENSITIVE_PATHS = [
    ".pentnote/local.json",
    ".pentnote/workspace.json",
    "attachments/",
    "raw/",
    "*.potfile",
    "hashes.txt",
    "*.hash",
]

GITIGNORE_ENTRIES = (
    *SENSITIVE_PATHS,
    ".pentnote/*.lock",
    ".pentnote/*.pid",
    ".pentnote/*.tmp",
    ".pentnote/ghostlog-*.jsonl",
    ".pentnote/cache/",
    ".pentnote/sync-conflicts.json",
    "*.log",
    "__pycache__/",
    ".pytest_cache/",
)

LOCAL_CONFIG_DEFAULTS = {
    "lhost": "",
    "lport": 8000,
    "ollama_model": "llama3",
    "sync_remote": "origin",
    "sync_branch": "",
}

LOCAL_EXAMPLE_JSONC = """// PentNote operator-specific secrets and local settings.
// This file is safe to copy to `.pentnote/local.json`.
// Do not commit `.pentnote/local.json`; it may contain listener IPs,
// ports, tokens, model choices, or other operator-only values.
{
  "lhost": "10.10.14.2",
  "lport": 8000,
  "ollama_model": "llama3",
  "sync_remote": "origin",
  "sync_branch": ""
}
"""


def initialize_engagement(
    root: Path,
    name: str,
    scope: list[str],
    *,
    client_name: str | None = None,
    engagement_type: EngagementType | str | None = None,
    start_date: str = "",
    operator: str | None = None,
    notes: str | None = None,
    target_groups: list[TargetGroup] | None = None,
) -> Engagement:
    """Create or update a PentNote engagement vault safely."""

    root = root.resolve()
    state_dir = root / ".pentnote"
    for directory in (state_dir, root / "notes", root / "reports", root / "raw"):
        directory.mkdir(parents=True, exist_ok=True)

    created_at = _now_iso()
    existing: dict[str, object] = {}
    config_path = state_dir / "config.json"
    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
            created_at = str(existing.get("created_at") or created_at)
        except json.JSONDecodeError:
            created_at = _now_iso()

    engagement_type_value = EngagementType(
        engagement_type
        or str(existing.get("engagement_type") or EngagementType.FULL_SCOPE.value)
    )
    client_name_value = (
        client_name if client_name is not None else existing.get("client_name")
    )
    operator_value = operator if operator is not None else existing.get("operator")
    notes_value = notes if notes is not None else existing.get("notes")
    start_date_value = start_date or str(existing.get("start_date") or "")
    target_group_values = _target_groups_from_config(
        target_groups
        if target_groups is not None
        else existing.get("target_groups", [])
    )
    config = {
        "name": name,
        "client_name": client_name_value,
        "engagement_type": engagement_type_value.value,
        "scope": scope,
        "start_date": start_date_value,
        "operator": operator_value,
        "notes": notes_value,
        "target_groups": [
            group.model_dump(mode="json") for group in target_group_values
        ],
        "created_at": created_at,
        "version": 1,
    }
    atomic_write_json(config_path, config)

    local_path = state_dir / "local.json"
    if not local_path.exists():
        atomic_write_json(local_path, LOCAL_CONFIG_DEFAULTS)

    # Static reference template, never read back by PentNote -- a plain
    # overwrite is fine since there is no unique content to lose.
    example_path = state_dir / "local.example.jsonc"
    example_path.write_text(LOCAL_EXAMPLE_JSONC, encoding="utf-8")

    findings_path = state_dir / "findings.json"
    if not findings_path.exists():
        atomic_write_json(findings_path, [])

    _write_gitignore(root)
    return Engagement(
        root=root,
        name=name,
        scope=scope,
        created_at=created_at,
        client_name=str(client_name_value) if client_name_value else None,
        engagement_type=engagement_type_value,
        start_date=start_date_value,
        operator=str(operator_value) if operator_value else None,
        notes=str(notes_value) if notes_value else None,
        target_groups=target_group_values,
    )


def _write_gitignore(vault_root: Path) -> None:
    """Ensure PentNote sensitive paths are protected by the vault gitignore."""

    ensure_operator_gitignore(vault_root)


def ensure_operator_gitignore(root: Path) -> Path:
    """Ensure the engagement gitignore protects operator-local state."""

    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    normalized = {line.strip() for line in existing}
    additions = [entry for entry in GITIGNORE_ENTRIES if entry not in normalized]
    if not additions:
        return path

    lines = existing[:]
    if lines and lines[-1].strip():
        lines.append("")
    if "# PentNote sensitive files" not in normalized:
        lines.append("# PentNote sensitive files")
    lines.extend(additions)
    atomic_write_text(path, "\n".join(lines).rstrip() + "\n")
    return path


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _target_groups_from_config(value: object) -> list[TargetGroup]:
    if not isinstance(value, list):
        return []
    groups = []
    for item in value:
        if isinstance(item, TargetGroup):
            groups.append(item)
        elif isinstance(item, dict):
            groups.append(TargetGroup.model_validate(item))
    return groups

"""Engagement workspace management."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pentnote.core.deduplicator import merge_findings
from pentnote.core.fileio import atomic_write_json
from pentnote.core.init_engine import LOCAL_CONFIG_DEFAULTS, initialize_engagement
from pentnote.core.models import (
    DefenseRow,
    Engagement,
    EngagementType,
    Finding,
    MitreMatch,
    Severity,
    TargetGroup,
)


class EngagementError(RuntimeError):
    """Raised when an engagement workspace cannot be loaded."""


def init_engagement(
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
    """Create or update an engagement vault."""

    return initialize_engagement(
        root,
        name,
        scope,
        client_name=client_name,
        engagement_type=engagement_type,
        start_date=start_date,
        operator=operator,
        notes=notes,
        target_groups=target_groups,
    )


def find_engagement_root(start: Path) -> Path | None:
    """Find the nearest parent containing a PentNote config."""

    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".pentnote" / "config.json").exists():
            return candidate
    return None


def load_engagement(root: Path | None = None) -> Engagement:
    """Load an engagement from a root path or the current tree."""

    resolved = root.resolve() if root else find_engagement_root(Path.cwd())
    if resolved is None:
        raise EngagementError("No PentNote engagement found. Run 'pentnote init NAME'.")
    config_path = resolved / ".pentnote" / "config.json"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EngagementError(f"Missing engagement config: {config_path}") from exc
    return Engagement(
        root=resolved,
        name=data["name"],
        scope=list(data.get("scope", [])),
        created_at=data.get("created_at", _now_iso()),
        client_name=data.get("client_name"),
        engagement_type=EngagementType(
            data.get("engagement_type", EngagementType.FULL_SCOPE.value)
        ),
        start_date=data.get("start_date", ""),
        operator=data.get("operator"),
        notes=data.get("notes"),
        target_groups=_target_groups_from_config(data.get("target_groups", [])),
    )


def maybe_load_engagement(root: Path | None = None) -> Engagement | None:
    """Load an engagement when one exists."""

    try:
        return load_engagement(root)
    except EngagementError:
        return None


def save_engagement_config(engagement: Engagement) -> None:
    """Persist engagement metadata to `.pentnote/config.json`."""

    config = {
        "name": engagement.name,
        "client_name": engagement.client_name,
        "engagement_type": engagement.engagement_type.value,
        "scope": engagement.scope,
        "start_date": engagement.start_date,
        "operator": engagement.operator,
        "notes": engagement.notes,
        "target_groups": [
            group.model_dump(mode="json") for group in engagement.target_groups
        ],
        "created_at": engagement.created_at,
        "version": 1,
    }
    atomic_write_json(engagement.config_path, config)


def load_local_config(engagement: Engagement) -> dict[str, Any]:
    """Load operator-local config values ignored by Git."""

    defaults: dict[str, Any] = dict(LOCAL_CONFIG_DEFAULTS)
    try:
        data = json.loads(engagement.local_config_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return defaults
    return {**defaults, **data}


def load_findings(engagement: Engagement) -> list[Finding]:
    """Load persisted findings."""

    if not engagement.findings_path.exists():
        return []
    try:
        data = json.loads(engagement.findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        backup = engagement.findings_path.with_suffix(
            f".corrupt.{int(datetime.now(UTC).timestamp())}"
        )
        engagement.findings_path.replace(backup)
        engagement.findings_path.write_text("[]\n", encoding="utf-8")
        raise EngagementError(
            f"Corrupt findings state backed up to {backup.name}."
        ) from exc
    return [_finding_from_dict(item) for item in data]


def save_findings(engagement: Engagement, findings: list[Finding]) -> None:
    """Persist findings to engagement state."""

    atomic_write_json(
        engagement.findings_path, [_finding_to_dict(item) for item in findings]
    )


def merge_and_save_findings(
    engagement: Engagement,
    incoming: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Merge incoming findings into engagement state."""

    existing = load_findings(engagement)
    result = merge_findings(existing, incoming)
    save_findings(engagement, result.merged)
    return result.new, result.duplicates


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


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    return Finding(
        title=data["title"],
        severity=Severity(data["severity"]),
        mitre_matches=[
            MitreMatch(
                technique_id=item["technique_id"],
                technique_name=item["technique_name"],
                tactic=item["tactic"],
                confidence=float(item["confidence"]),
                source=item["source"],
            )
            for item in data.get("mitre_matches", [])
        ],
        affected_hosts=list(data.get("affected_hosts", [])),
        evidence=data.get("evidence", ""),
        next_steps=list(data.get("next_steps", [])),
        defenses=[_defense_from_dict(item) for item in data.get("defenses", [])],
        chain_member=data.get("chain_member"),
        hash=data["hash"],
        source_command=data.get("source_command"),
    )


def _defense_to_dict(defense: DefenseRow | str) -> dict[str, str]:
    if isinstance(defense, str):
        defense_id, _, description = defense.partition(":")
        return {
            "technique_id": "",
            "defend_id": defense_id.strip(),
            "description": description.strip() or defense,
        }
    return {
        "technique_id": defense.technique_id,
        "defend_id": defense.defend_id,
        "description": defense.description,
    }


def _defense_from_dict(data: Any) -> DefenseRow:
    if isinstance(data, str):
        defense_id, _, description = data.partition(":")
        return DefenseRow("", defense_id.strip(), description.strip() or data)
    return DefenseRow(
        technique_id=str(data.get("technique_id") or ""),
        defend_id=str(data.get("defend_id") or data.get("defense_id") or ""),
        description=str(data.get("description") or ""),
    )

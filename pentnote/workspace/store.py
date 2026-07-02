"""Workspace JSON store for interactive engagement data."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import click

from pentnote.core.engagement import Engagement, EngagementError, load_engagement
from pentnote.core.models import WorkspaceState, normalize_secret_type_value

EMPTY_WORKSPACE: dict[str, Any] = {
    "credentials": [],
    "notes": [],
    "loot": [],
    "log": [],
    "pending_review": [],
    "quality_stats": {
        "written": 0,
        "queued": 0,
        "rejected": 0,
        "confidence_total": 0.0,
        "confidence_count": 0,
    },
}


class WorkspaceStore:
    """Read and write `.pentnote/workspace.json`."""

    def __init__(self, vault_path: Path):
        self.root = vault_path.resolve()
        self.path = self.root / ".pentnote" / "workspace.json"

    @classmethod
    def active(cls) -> tuple[Engagement, WorkspaceStore]:
        engagement = load_engagement()
        return engagement, cls(engagement.root)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return _legacy_empty()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            backup = self.path.with_suffix(
                f".corrupt.{int(datetime.now(UTC).timestamp())}"
            )
            self.path.replace(backup)
            print(
                f"[!] Corrupt workspace backed up to {backup.name}",
                file=sys.stderr,
            )
            return _empty()
        merged = _empty()
        for key in merged:
            if key == "quality_stats":
                merged[key] = {
                    **merged["quality_stats"],
                    **dict(data.get("quality_stats", {})),
                }
            else:
                merged[key] = list(data.get(key, []))
        return WorkspaceState.model_validate(merged).model_dump(mode="json")

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(self.path)
        if os.name != "nt":
            os.chmod(self.path, 0o600)

    def add_credential(self, cred: dict[str, Any]) -> None:
        data = self.load()
        cred = _credential_defaults(cred)
        data["credentials"] = _dedupe_by_id([*data["credentials"], cred])
        self.save(data)

    def add_note(self, note: dict[str, Any]) -> None:
        data = self.load()
        data["notes"].append({**note, "id": note.get("id") or str(uuid4())})
        self.save(data)

    def delete_note(self, note_id: str) -> dict[str, Any] | None:
        data = self.load()
        for index, item in enumerate(data["notes"]):
            if item.get("id") != note_id:
                continue
            deleted = data["notes"].pop(index)
            self.save(data)
            return deleted
        return None

    def add_loot(self, loot: dict[str, Any]) -> None:
        data = self.load()
        data["loot"].append({**loot, "id": loot.get("id") or str(uuid4())})
        self.save(data)

    def add_log(self, entry: dict[str, Any]) -> None:
        data = self.load()
        data["log"].append({**entry, "id": entry.get("id") or str(uuid4())})
        self.save(data)

    def get_credentials(
        self, filters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        filters = filters or {}
        credentials = [*self.load()["credentials"], *self._credentials_from_findings()]
        credentials = _dedupe_by_id(
            [_credential_defaults(item) for item in credentials]
        )
        if value := filters.get("type"):
            credentials = [
                item for item in credentials if item.get("secret_type") == value
            ]
        if filters.get("cracked"):
            credentials = [item for item in credentials if item.get("cracked")]
        if value := filters.get("host"):
            credentials = [
                item for item in credentials if item.get("source_host") == value
            ]
        if value := filters.get("domain"):
            credentials = [
                item
                for item in credentials
                if (item.get("domain") or "").casefold() == value.casefold()
            ]
        if value := filters.get("user"):
            credentials = [
                item
                for item in credentials
                if value.casefold() in item.get("username", "").casefold()
            ]
        if value := filters.get("tag"):
            credentials = [
                item for item in credentials if value in item.get("tags", [])
            ]
        if value := filters.get("tool"):
            credentials = [
                item for item in credentials if item.get("source_tool") == value
            ]
        if filters.get("uncracked"):
            credentials = [item for item in credentials if not item.get("cracked")]
        return credentials

    def get_notes(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        notes = list(self.load()["notes"])
        if value := filters.get("host"):
            notes = [item for item in notes if item.get("target") == value]
        if value := filters.get("tag"):
            notes = [item for item in notes if value in item.get("tags", [])]
        if value := filters.get("finding"):
            notes = [
                item
                for item in notes
                if item.get("finding") == value or item.get("target") == value
            ]
        return sorted(notes, key=lambda item: item.get("date", ""))

    def get_loot(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        loot = list(self.load()["loot"])
        if value := filters.get("host"):
            loot = [item for item in loot if item.get("host") == value]
        if value := filters.get("type"):
            loot = [item for item in loot if item.get("type") == value]
        return loot

    def get_log(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        entries = list(self.load()["log"])
        if value := filters.get("host"):
            entries = [item for item in entries if item.get("host") == value]
        if value := filters.get("tag"):
            entries = [item for item in entries if value in item.get("tags", [])]
        if filters.get("today"):
            today = now_iso()[:10]
            entries = [
                item for item in entries if item.get("date", "").startswith(today)
            ]
        return sorted(entries, key=lambda item: item.get("date", ""))

    def _credentials_from_findings(self) -> list[dict[str, Any]]:
        # The current findings schema does not persist credentials; keep this
        # hook so old/new workspaces can merge future parsed credential records.
        findings_path = self.root / ".pentnote" / "findings.json"
        if not findings_path.exists():
            return []
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            backup = findings_path.with_suffix(
                f".corrupt.{int(datetime.now(UTC).timestamp())}"
            )
            findings_path.replace(backup)
            print(
                f"[!] Corrupt findings state backed up to {backup.name}",
                file=sys.stderr,
            )
            return []
        credentials: list[dict[str, Any]] = []
        for item in findings:
            for cred in item.get("credentials", []):
                if isinstance(cred, dict):
                    credentials.append(cred)
        return credentials


def active_workspace() -> tuple[Engagement, WorkspaceStore]:
    try:
        return WorkspaceStore.active()
    except EngagementError as exc:
        raise click.ClickException(str(exc)) from exc


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def credential_id(username: str, domain: str | None, secret_type: str) -> str:
    secret_type = normalize_secret_type_value(secret_type)
    payload = "|".join(
        [username.casefold(), (domain or "").casefold(), secret_type.casefold()]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def note_id() -> str:
    return str(uuid4())


def target_type(target: str) -> str:
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", target):
        return "host"
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}", target):
        return "host"
    return "finding"


def host_note_path(notes_dir: Path, target: str) -> Path:
    return notes_dir / "hosts" / f"{slugify(target)}.md"


def append_to_host_note(notes_dir: Path, target: str, content: str) -> None:
    path = host_note_path(notes_dir, target)
    if not path.exists():
        return
    append_to_note_path(path, content)


def append_to_note_path(path: Path, content: str) -> None:
    text = path.read_text(encoding="utf-8")
    addition = f"- {now_iso()} - {content}\n"
    if "## Notes" in text:
        before, after = text.split("## Notes", 1)
        path.write_text(
            f"{before}## Notes{after.rstrip()}\n{addition}", encoding="utf-8"
        )
    else:
        path.write_text(f"{text.rstrip()}\n\n## Notes\n{addition}", encoding="utf-8")


def finding_note_path(notes_dir: Path, target: str) -> Path | None:
    finding_dir = notes_dir / "findings"
    if not finding_dir.exists():
        return None
    normalized = slugify(target)
    for path in finding_dir.rglob("*.md"):
        if path.name == "_index.md":
            continue
        if path.name.startswith(target) or normalized in path.stem:
            return path
    return None


def append_timeline_entry(notes_dir: Path, entry: dict[str, Any]) -> None:
    notes_dir.mkdir(parents=True, exist_ok=True)
    path = notes_dir / "TIMELINE.md"
    if not path.exists():
        path.write_text(
            "| Time | Source | Message |\n| --- | --- | --- |\n",
            encoding="utf-8",
        )
    date = datetime.fromisoformat(entry["date"]).strftime("%Y-%m-%d %H:%M")
    host = f" ({entry['host']})" if entry.get("host") else ""
    source = _timeline_source(entry)
    line = f"| {date} | {source} | {entry['message']}{host} |\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def _timeline_source(entry: dict[str, Any]) -> str:
    source = str(entry.get("source") or "").strip()
    if source:
        return source
    tags = {str(tag).casefold() for tag in entry.get("tags", [])}
    if "ghostlog" in tags:
        return "ghostlog"
    return "manual"


def write_loot_markdown(notes_dir: Path, loot: list[dict[str, Any]]) -> Path:
    notes_dir.mkdir(parents=True, exist_ok=True)
    path = notes_dir / "LOOT.md"
    lines = [
        "# Loot",
        "",
        "| Type | Host | Value/Path | User | Date | Notes |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in loot:
        lines.append(
            "| {type} | {host} | {value} | {user} | {date} | {notes} |".format(
                type=item.get("type", ""),
                host=item.get("host", ""),
                value=item.get("value") or "",
                user=item.get("user") or "",
                date=item.get("date", ""),
                notes=item.get("notes") or "",
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_credentials_csv(path: Path, credentials: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "id",
        "username",
        "domain",
        "secret_type",
        "source_host",
        "source_tool",
        "cracked",
        "cracked_value",
        "tags",
        "date_added",
        "notes",
        "related_finding_hash",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in credentials:
            row = {field: item.get(field, "") for field in fields}
            row["tags"] = ",".join(item.get("tags", []))
            writer.writerow(row)
    return path


def slugify(value: str) -> str:
    slug = []
    previous_dash = False
    for char in value.casefold().strip():
        if char.isalnum():
            slug.append(char)
            previous_dash = False
        elif not previous_dash:
            slug.append("-")
            previous_dash = True
    return "".join(slug).strip("-") or "note"


def credential_from_model(credential: Any, source_tool: str) -> dict[str, Any]:
    if hasattr(credential, "model_dump"):
        data = credential.model_dump(mode="json")
    else:
        data = dict(credential)
    return _credential_defaults({**data, "source_tool": source_tool})


def _credential_defaults(cred: dict[str, Any]) -> dict[str, Any]:
    username = str(cred.get("username") or "")
    domain = cred.get("domain")
    secret_type = normalize_secret_type_value(cred.get("secret_type") or "")
    return {
        "id": cred.get("id") or credential_id(username, domain, secret_type),
        "username": username,
        "domain": domain,
        "secret": str(cred.get("secret") or ""),
        "secret_type": secret_type,
        "source_host": str(cred.get("source_host") or "unknown"),
        "source_tool": str(cred.get("source_tool") or "manual"),
        "cracked": bool(cred.get("cracked", False)),
        "cracked_value": cred.get("cracked_value"),
        "tags": list(cred.get("tags", [])),
        "date_added": cred.get("date_added") or now_iso(),
        "notes": str(cred.get("notes") or ""),
        "related_finding_hash": cred.get("related_finding_hash"),
    }


def _dedupe_by_id(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for item in items:
        seen[item["id"]] = {**seen.get(item["id"], {}), **item}
    return list(seen.values())


def _empty() -> dict[str, Any]:
    return json.loads(json.dumps(EMPTY_WORKSPACE))


def _legacy_empty() -> dict[str, list[dict[str, Any]]]:
    return {"credentials": [], "notes": [], "loot": [], "log": []}

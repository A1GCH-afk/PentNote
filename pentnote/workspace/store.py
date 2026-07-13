"""Workspace JSON store for interactive engagement data."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import click

from pentnote.core.engagement import Engagement, EngagementError, load_engagement
from pentnote.core.fileio import atomic_write_json, atomic_write_text
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
        atomic_write_json(self.path, data)
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

    def delete_loot(self, loot_id: str) -> dict[str, Any] | None:
        data = self.load()
        for index, item in enumerate(data["loot"]):
            if item.get("id") != loot_id:
                continue
            deleted = data["loot"].pop(index)
            self.save(data)
            return deleted
        return None

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
        if value := filters.get("user"):
            loot = [item for item in loot if item.get("user") == value]
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


def resolve_host_note_path(
    notes_dir: Path, target: str, *, known_ip: str | None = None
) -> tuple[Path, str | None]:
    """Map a host identifier to the canonical host note, avoiding duplicates.

    A host is often referred to by different identifiers across tools/commands
    (an IP, a NetBIOS name, an FQDN, in any case). This returns the existing
    note that already records ``target`` as one of its identities so writes
    land on one note instead of fragmenting.

    Auto-merges only on a **data-backed link**, never on hostname string-equality
    alone (two distinct hosts routinely share a NetBIOS/host name -- cloned
    images, reused defaults, a DC pair -- so an equal name is not proof of the
    same host). Two signals qualify:

    * **Network-layer identity** -- ``target`` is an IP equal to the note's
      recorded ``host:`` IP. Within an engagement one IP is one host, and the
      note captured that IP from tool output.
    * **Corroborated hostname** -- ``target`` matches the note's ``hostname:``
      or an alias *and* the caller passes ``known_ip`` matching the note's IP,
      i.e. the incoming side asserts the same IP<->hostname pairing a tool
      observed.

    A hostname/alias match without a corroborating IP, an FQDN whose short label
    matches an existing note's hostname, or an ambiguous match against several
    notes is **never** auto-merged: it returns the fresh slug-derived path plus a
    warning so the operator can reconcile manually, because a silent wrong-merge
    corrupts a deliverable worse than a duplicate.

    Returns ``(path, warning_or_none)``.
    """

    default_path = host_note_path(notes_dir, target)
    hosts_dir = notes_dir / "hosts"
    # A note already keyed by this exact identifier is unambiguously the target.
    if default_path.exists() or not hosts_dir.exists():
        return default_path, None

    merges: list[Path] = []
    possible: list[str] = []
    for note_path in sorted(hosts_dir.glob("*.md")):
        identity = _host_note_identity(note_path.read_text(encoding="utf-8"))
        ip_cf = identity["ip"].strip().casefold()
        name_ids = _note_name_ids(identity)
        if _confirmed_host_link(target, ip_cf, name_ids, known_ip=known_ip):
            merges.append(note_path)
        elif _possible_host_link(target, name_ids, identity["hostname"]):
            possible.append(identity["hostname"] or identity["ip"] or note_path.stem)

    if len(merges) == 1:
        return merges[0], None
    if len(merges) > 1:
        names = ", ".join(path.name for path in merges)
        return default_path, (
            f"possible duplicate host: {target!r} matches multiple host notes "
            f"({names}); not auto-merging"
        )
    if possible:
        return default_path, (
            f"possible duplicate host: {target!r} and {possible[0]!r} may be the "
            "same target; not auto-merging without a confirmed IP link"
        )
    return default_path, None


def _host_note_identity(text: str) -> dict[str, Any]:
    return {
        "ip": _frontmatter_scalar(text, "host"),
        "hostname": _frontmatter_scalar(text, "hostname"),
        "aliases": _also_known_as(text),
    }


def _note_name_ids(identity: dict[str, Any]) -> set[str]:
    """Case-folded set of a note's name identifiers (hostname + aliases)."""

    return {
        value.casefold()
        for value in (identity["hostname"], *identity["aliases"])
        if value
    }


def _confirmed_host_link(
    target: str,
    note_ip_cf: str,
    note_name_ids: set[str],
    *,
    known_ip: str | None = None,
) -> bool:
    """True when ``target`` has a **data-backed link** to a host note's identity.

    A confirmed link authorizes treating the incoming write as the same host:
    either ``target`` is an IP equal to the note's recorded IP (one IP is one
    host within an engagement), or it matches one of the note's names *and* the
    caller-supplied ``known_ip`` equals the note's IP (the incoming side asserts
    the same IP<->name pairing a tool observed). Hostname string-equality alone
    never qualifies. This is the single criterion both the auto-merge rule and
    the pre-fix-merge detector rely on, so the two cannot drift apart.
    """

    target_cf = target.strip().casefold()
    known_ip_cf = known_ip.strip().casefold() if known_ip else ""
    ip_match = bool(note_ip_cf) and _looks_like_ip(target) and target_cf == note_ip_cf
    name_match = target_cf in note_name_ids
    corroborated = name_match and bool(known_ip_cf) and known_ip_cf == note_ip_cf
    return ip_match or corroborated


def _possible_host_link(
    target: str, note_name_ids: set[str], note_hostname: str
) -> bool:
    """True when ``target`` *might* be a note's host but lacks a data-backed link.

    A name/alias string match, or a shared first DNS label, is enough to suspect
    the same host and warn -- never enough to auto-merge. Callers must check
    :func:`_confirmed_host_link` first; a possible-but-not-confirmed link is
    exactly the ambiguity that the pre-1.1.0 rule wrongly auto-merged on.
    """

    return target.strip().casefold() in note_name_ids or _shares_first_label(
        target, note_hostname
    )


@dataclass(frozen=True)
class SuspectedHostMerge:
    """A host note whose identity collides by name with another, without an IP link."""

    note_path: Path
    ip: str
    hostname: str
    collisions: tuple[str, ...]
    confidence: str


def find_suspected_host_merges(notes_dir: Path) -> list[SuspectedHostMerge]:
    """Flag host notes that the pre-1.1.0 string-equality rule could have merged.

    Before 1.1.0, a bare-name write (``note <name>``, an unsupported-tool record,
    or a Ghost Log apply) auto-merged onto any existing note whose recorded name
    it case-insensitively matched -- even across two genuinely distinct hosts.

    This reports, **read-only**, every host note whose name identifiers collide
    with another note's while their IPs differ: a *possible* link with no
    *confirmed* (IP) link, judged by the exact same criterion the auto-merge rule
    uses (:func:`_confirmed_host_link` / :func:`_possible_host_link`). Those are
    the pairs where an old bare-name write could have landed on the wrong note.

    Confidence is ``"high"`` when the notes share an exact name/alias (the string
    the old rule matched on), ``"low"`` when they only share a first DNS label
    (which the old rule warned about but did not merge). Nothing is modified;
    conflations must be reviewed and split by hand -- see the migration notes.
    """

    hosts_dir = notes_dir / "hosts"
    if not hosts_dir.exists():
        return []

    notes: list[tuple[Path, dict[str, Any], str, set[str]]] = []
    for note_path in sorted(hosts_dir.glob("*.md")):
        identity = _host_note_identity(note_path.read_text(encoding="utf-8"))
        notes.append(
            (
                note_path,
                identity,
                identity["ip"].strip().casefold(),
                _note_name_ids(identity),
            )
        )

    flagged: list[SuspectedHostMerge] = []
    for path_a, id_a, ip_a, names_a in notes:
        collisions: list[str] = []
        confidence = "low"
        for path_b, id_b, ip_b, names_b in notes:
            if path_b == path_a:
                continue
            b_targets = [t for t in (id_b["hostname"], *id_b["aliases"]) if t]
            # Frame B's identifiers as incoming writes against A: a NAME link with
            # no data-backed IP link is exactly the pre-fix mis-merge condition.
            linked = [
                t
                for t in b_targets
                if _possible_host_link(t, names_a, id_a["hostname"])
                and not _confirmed_host_link(t, ip_a, names_a, known_ip=ip_b)
            ]
            if not linked:
                continue
            if names_a & names_b:
                confidence = "high"
            other = id_b["hostname"] or id_b["ip"] or path_b.stem
            collisions.append(f"{other} ({path_b.name})")
        if collisions:
            flagged.append(
                SuspectedHostMerge(
                    note_path=path_a,
                    ip=id_a["ip"],
                    hostname=id_a["hostname"],
                    collisions=tuple(sorted(collisions)),
                    confidence=confidence,
                )
            )
    return flagged


def _frontmatter_scalar(text: str, key: str) -> str:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    prefix = f"{key}:"
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def _also_known_as(text: str) -> list[str]:
    for line in text.splitlines():
        if line.startswith("| Also Known As |"):
            cells = line.split("|")
            if len(cells) >= 3:
                return [alias.strip() for alias in cells[2].split(",") if alias.strip()]
    return []


def _looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value.strip()))


def _shares_first_label(target: str, hostname: str) -> bool:
    """True when target and hostname share a first DNS label but differ overall.

    Signals a *possible* (unconfirmed) same-host, e.g. ``DC01.a.local`` vs a
    note whose hostname is ``DC01`` -- worth warning about, never auto-merging.
    """

    if not hostname or _looks_like_ip(target):
        return False
    target_cf = target.strip().casefold()
    hostname_cf = hostname.casefold()
    if target_cf == hostname_cf:
        return False
    first = target_cf.split(".")[0]
    return bool(first) and first == hostname_cf.split(".")[0]


def append_to_host_note(notes_dir: Path, target: str, content: str) -> None:
    path, warning = resolve_host_note_path(notes_dir, target)
    if warning:
        print(f"[!] {warning}", file=sys.stderr)
    if not path.exists():
        return
    append_to_note_path(path, content)


def append_to_note_path(path: Path, content: str) -> None:
    text = path.read_text(encoding="utf-8")
    addition = f"- {now_iso()} - {content}\n"
    if "## Notes" in text:
        before, after = text.split("## Notes", 1)
        atomic_write_text(path, f"{before}## Notes{after.rstrip()}\n{addition}")
    else:
        atomic_write_text(path, f"{text.rstrip()}\n\n## Notes\n{addition}")


UNSUPPORTED_TOOLS_HEADING = "## Unparsed / Unsupported Tools"


def record_unsupported_tool(
    notes_dir: Path, host: str, tool: str, command: str = ""
) -> Path:
    """Record an unparsed/unsupported tool run in a host note.

    Adds a bullet under an ``## Unparsed / Unsupported Tools`` section so the
    operator can later see which tool (and invocation) ran against the host
    even though PentNote has no dedicated parser for it. The host note is
    created if it does not yet exist.
    """

    path, warning = resolve_host_note_path(notes_dir, host)
    if warning:
        print(f"[!] {warning}", file=sys.stderr)
    entry = f"- {now_iso()} - {tool}"
    if command:
        entry += f" — `{command}`"
    if path.exists():
        text = path.read_text(encoding="utf-8")
        entries = [*unsupported_tool_entries(text), entry]
        atomic_write_text(path, _set_unsupported_section(text, entries))
    else:
        atomic_write_text(path, _minimal_host_note(host, [entry]))
    return path


def unsupported_tool_entries(text: str) -> list[str]:
    """Return the bullet lines currently under the unsupported-tools heading."""

    if UNSUPPORTED_TOOLS_HEADING not in text:
        return []
    body = text.split(UNSUPPORTED_TOOLS_HEADING, 1)[1]
    entries: list[str] = []
    for line in body.splitlines():
        if line.startswith("## "):
            break
        if line.strip().startswith("- "):
            entries.append(line.rstrip())
    return entries


def apply_unsupported_tool_section(rendered: str, existing_note: str | None) -> str:
    """Carry an existing unsupported-tools section into a regenerated host note."""

    entries = unsupported_tool_entries(existing_note) if existing_note else []
    if not entries:
        return rendered
    return _set_unsupported_section(rendered, entries)


def _set_unsupported_section(text: str, entries: list[str]) -> str:
    """Insert/replace the unsupported-tools section just above ``## Notes``."""

    text = _strip_unsupported_section(text)
    section = UNSUPPORTED_TOOLS_HEADING + "\n" + "\n".join(entries) + "\n"
    if "## Notes" in text:
        before, after = text.split("## Notes", 1)
        return f"{before.rstrip()}\n\n{section}\n## Notes{after}"
    return f"{text.rstrip()}\n\n{section}"


def _strip_unsupported_section(text: str) -> str:
    if UNSUPPORTED_TOOLS_HEADING not in text:
        return text
    before, rest = text.split(UNSUPPORTED_TOOLS_HEADING, 1)
    tail = ""
    remainder_lines = rest.splitlines()
    for index, line in enumerate(remainder_lines):
        if line.startswith("## "):
            tail = "\n".join(remainder_lines[index:])
            break
    result = before.rstrip()
    if tail:
        result += "\n\n" + tail
    return result.rstrip() + "\n"


def _minimal_host_note(host: str, entries: list[str]) -> str:
    section = UNSUPPORTED_TOOLS_HEADING + "\n" + "\n".join(entries) + "\n"
    return (
        "---\n"
        "tags: [host]\n"
        f"host: {host}\n"
        f"date: {now_iso()}\n"
        "---\n\n"
        f"# {host}\n\n"
        f"{section}\n"
        "## Notes\n"
        "<!-- analyst notes here -->\n"
    )


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
    atomic_write_text(path, "\n".join(lines) + "\n")
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


def loot_from_model(loot: Any) -> dict[str, Any]:
    data = loot.model_dump(mode="json") if hasattr(loot, "model_dump") else dict(loot)
    data["date"] = data.get("date") or now_iso()
    return data


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

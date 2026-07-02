"""Hashcat potfile synchronization for PentNote credentials."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from pentnote.core.engagement import Engagement, merge_and_save_findings
from pentnote.models import Finding, Severity
from pentnote.workspace.store import (
    WorkspaceStore,
    append_timeline_entry,
    now_iso,
    slugify,
)


class PotfileEntry(BaseModel):
    """One parsed Hashcat potfile line."""

    hash_value: str = Field(min_length=1)
    plaintext: str = Field(min_length=1)

    @field_validator("hash_value", "plaintext")
    @classmethod
    def strip_value(cls, value: str) -> str:
        return value.strip()


class CrackedCredential(BaseModel):
    """Workspace credential updated from a potfile match."""

    credential_id: str
    username: str
    domain: str | None = None
    source_host: str | None = None
    secret_type: str
    plaintext: str = Field(min_length=1)


class PotfileImportResult(BaseModel):
    """Summary returned by a potfile import."""

    parsed: int = 0
    matched: int = 0
    updated: int = 0
    findings_created: int = 0
    credentials: list[CrackedCredential] = Field(default_factory=list)


def import_hashcat_potfile(
    potfile_path: str,
    *,
    engagement: Engagement | None = None,
) -> PotfileImportResult:
    """Import cracked Hashcat entries into the active PentNote workspace."""

    if engagement is None:
        engagement, _store = WorkspaceStore.active()
    store = WorkspaceStore(engagement.root)
    entries = parse_hashcat_potfile(Path(potfile_path))
    if not entries:
        return PotfileImportResult()

    data = store.load()
    updated_credentials: list[CrackedCredential] = []
    parsed = len(entries)
    matched = 0
    updated = 0

    for credential in data["credentials"]:
        match = _matching_entry(credential, entries)
        if match is None:
            continue
        matched += 1
        if (
            credential.get("cracked") is True
            and credential.get("cracked_value") == match.plaintext
        ):
            continue
        credential["cracked"] = True
        credential["cracked_value"] = match.plaintext
        credential["plaintext"] = match.plaintext
        credential["cracked_at"] = now_iso()
        tags = list(credential.get("tags", []))
        for tag in ("cracked", "hashcat"):
            if tag not in tags:
                tags.append(tag)
        credential["tags"] = tags
        cracked = _cracked_credential(credential, match.plaintext)
        updated_credentials.append(cracked)
        _update_credential_note(engagement.notes_dir, credential, match.plaintext)
        updated += 1

    if updated_credentials:
        store.save(data)

    new_findings, _duplicates = merge_and_save_findings(
        engagement,
        [_finding_for_cracked_credential(item) for item in updated_credentials],
    )
    for item in updated_credentials:
        append_timeline_entry(
            engagement.notes_dir,
            {
                "date": now_iso(),
                "message": f"Credential cracked for {_principal(item)}",
                "host": item.source_host,
                "tags": ["credential", "cracked", "hashcat"],
            },
        )

    return PotfileImportResult(
        parsed=parsed,
        matched=matched,
        updated=updated,
        findings_created=len(new_findings),
        credentials=updated_credentials,
    )


def parse_hashcat_potfile(path: Path) -> list[PotfileEntry]:
    """Parse Hashcat ``hash:plaintext`` lines."""

    entries: list[PotfileEntry] = []
    if not path.exists():
        raise FileNotFoundError(path)
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        hash_value, plaintext = line.rsplit(":", 1)
        try:
            entries.append(PotfileEntry(hash_value=hash_value, plaintext=plaintext))
        except ValueError:
            continue
    return entries


def _matching_entry(
    credential: dict[str, Any],
    entries: list[PotfileEntry],
) -> PotfileEntry | None:
    secret = str(credential.get("secret") or "").strip()
    if not secret:
        return None
    username = str(credential.get("username") or "").strip()
    domain = str(credential.get("domain") or "").strip()
    candidates = {
        secret.casefold(),
        f"{username}:{secret}".casefold(),
        f"{domain}\\{username}:{secret}".casefold(),
        f"{domain}:{username}:{secret}".casefold(),
    }
    for entry in entries:
        value = entry.hash_value.casefold()
        if value in candidates or value.endswith(f":{secret.casefold()}"):
            return entry
    return None


def _cracked_credential(
    credential: dict[str, Any],
    plaintext: str,
) -> CrackedCredential:
    return CrackedCredential(
        credential_id=str(credential.get("id") or ""),
        username=str(credential.get("username") or ""),
        domain=credential.get("domain"),
        source_host=str(credential.get("source_host") or ""),
        secret_type=str(credential.get("secret_type") or ""),
        plaintext=plaintext,
    )


def _finding_for_cracked_credential(credential: CrackedCredential) -> Finding:
    principal = _principal(credential)
    evidence = (
        f"Hashcat potfile matched stored {credential.secret_type} material for "
        f"{principal}. Plaintext is stored in the credential workspace."
    )
    return Finding(
        title=f"Credential cracked: {principal}",
        severity=Severity.HIGH,
        mitre_matches=[],
        affected_hosts=[credential.source_host] if credential.source_host else [],
        evidence=evidence,
        next_steps=[
            "Validate access with the cracked credential from an approved operator host.",
            "Check credential reuse across SMB, WinRM, RDP, web login panels, and sudo paths.",
        ],
        defenses=[],
        chain_member="credential-access",
        hash=_finding_hash(principal, credential.secret_type),
    )


def _finding_hash(principal: str, secret_type: str) -> str:
    payload = f"cracked|{principal.casefold()}|{secret_type.casefold()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _update_credential_note(
    notes_dir: Path,
    credential: dict[str, Any],
    plaintext: str,
) -> None:
    path = _credential_note_path(notes_dir, credential)
    if path is None:
        path = _default_credential_note_path(notes_dir, credential)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"# Credential - {credential.get('username', 'unknown')}\n\n" "## Notes\n",
            encoding="utf-8",
        )

    text = path.read_text(encoding="utf-8")
    text = _ensure_frontmatter_tag(text, "cracked")
    marker = "<!-- pentnote:cracked-status -->"
    status = (
        f"{marker}\n"
        f"> ✅ CRACKED via Hashcat on {now_iso()}. "
        "Plaintext is stored in `.pentnote/workspace.json`.\n"
    )
    if marker in text:
        before, _marker, after = text.partition(marker)
        remainder = after.splitlines()[2:] if len(after.splitlines()) >= 2 else []
        text = before.rstrip() + "\n\n" + status + "\n".join(remainder).lstrip()
    elif "## Details" in text:
        text = text.replace("## Details", status + "\n## Details", 1)
    else:
        text = text.rstrip() + "\n\n" + status

    if "| Cracked |" in text:
        text = _replace_table_row(text, "Cracked", "✅")
    if "| Cracked Value |" in text:
        text = _replace_table_row(text, "Cracked Value", plaintext)
    elif "| Cracked |" in text:
        text = text.replace(
            "| Cracked | ✅ |",
            f"| Cracked | ✅ |\n| Cracked Value | {plaintext} |",
            1,
        )
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _credential_note_path(notes_dir: Path, credential: dict[str, Any]) -> Path | None:
    username = slugify(str(credential.get("username") or ""))
    secret_type = str(credential.get("secret_type") or "other")
    folder = {
        "ntlm": "ntlm",
        "plaintext": "plaintext",
        "kerberos": "kerberos",
        "net-ntlmv2": "net-ntlmv2",
        "net-ntlmv1": "net-ntlmv1",
        "sha256": "hashes",
        "sha1": "hashes",
        "md5": "hashes",
        "bcrypt": "hashes",
        "aes256": "kerberos",
        "dpapi": "dpapi",
    }.get(secret_type, "other")
    candidates = [
        notes_dir / "credentials" / folder / f"{username}.md",
        _default_credential_note_path(notes_dir, credential),
        notes_dir / "credentials" / f"{username}.md",
        notes_dir
        / "credentials"
        / f"{slugify(str(credential.get('domain') or 'local'))}-{slugify(str(credential.get('username') or ''))}.md",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _default_credential_note_path(notes_dir: Path, credential: dict[str, Any]) -> Path:
    secret_type = str(credential.get("secret_type") or "other")
    folder = {
        "ntlm": "ntlm",
        "plaintext": "plaintext",
        "kerberos": "kerberos",
        "net-ntlmv2": "net-ntlmv2",
        "net-ntlmv1": "net-ntlmv1",
        "sha256": "hashes",
        "sha1": "hashes",
        "md5": "hashes",
        "bcrypt": "hashes",
        "aes256": "kerberos",
        "dpapi": "dpapi",
    }.get(secret_type, "other")
    username = str(credential.get("username") or "unknown")
    return notes_dir / "credentials" / folder / f"{slugify(username)}.md"


def _ensure_frontmatter_tag(text: str, tag: str) -> str:
    if not text.startswith("---\n"):
        return text
    _prefix, _separator, rest = text.partition("---\n")
    frontmatter, separator, body = rest.partition("---\n")
    if not separator:
        return text
    lines = frontmatter.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("tags:"):
            continue
        if tag in line:
            return text
        if line.rstrip().endswith("]"):
            lines[index] = line.rstrip()[:-1] + f", {tag}]"
        else:
            lines[index] = f"{line}, {tag}"
        return "---\n" + "\n".join(lines) + "\n---\n" + body
    lines.insert(0, f"tags: [{tag}]")
    return "---\n" + "\n".join(lines) + "\n---\n" + body


def _replace_table_row(text: str, field: str, value: str) -> str:
    lines = text.splitlines()
    prefix = f"| {field} |"
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"| {field} | {value} |"
            break
    return "\n".join(lines)


def _principal(credential: CrackedCredential) -> str:
    if credential.domain:
        return f"{credential.domain}\\{credential.username}"
    return credential.username

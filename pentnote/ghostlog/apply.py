"""Apply Ghost Log extraction results to the PentNote workspace."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pentnote.core.engagement import Engagement, merge_and_save_findings
from pentnote.core.fileio import atomic_write_text
from pentnote.ghostlog.llm import GhostLogExtraction
from pentnote.models import (
    ExtractionConfidence,
    Finding,
    QualityGatedExtraction,
    Severity,
)
from pentnote.workspace.store import (
    WorkspaceStore,
    append_timeline_entry,
    append_to_host_note,
    credential_id,
    host_note_path,
    now_iso,
)

QUALITY_THRESHOLD_WRITE = 0.6
QUALITY_THRESHOLD_QUEUE = 0.3
REVIEW_EXPIRY_DAYS = 7


def apply_extraction(
    engagement: Engagement,
    extraction: GhostLogExtraction,
    source_command: str | None = None,
    *,
    quality_gate: bool = True,
    quiet: bool = True,
) -> tuple[int, int]:
    """Persist extracted credentials, findings, and notes."""

    store = WorkspaceStore(engagement.root)
    for credential in extraction.credentials:
        credential_data = {
            "id": credential_id(
                credential.username, credential.target, credential.secret_type
            ),
            "username": credential.username,
            "domain": None,
            "secret": credential.secret,
            "secret_type": credential.secret_type,
            "source_host": credential.target,
            "source_tool": "ghostlog",
            "cracked": False,
            "cracked_value": None,
            "tags": ["ghostlog"],
            "date_added": now_iso(),
            "notes": "",
        }
        if _should_write_item(
            store,
            "credential",
            credential_data,
            source_command,
            quality_gate=quality_gate,
            quiet=quiet,
        ):
            store.add_credential(credential_data)

    findings: list[Finding] = []
    written_finding_pairs = []
    for item in extraction.findings:
        finding = Finding(
            title=item.title,
            severity=_severity(item.severity),
            mitre_matches=[],
            affected_hosts=[item.target] if item.target else [],
            evidence=item.evidence,
            next_steps=[],
            defenses=[],
            chain_member=None,
            hash=_finding_hash(
                item.title, item.evidence, [item.target] if item.target else []
            ),
            source_command=source_command[:200] if source_command else None,
        )
        if _should_write_item(
            store,
            "finding",
            {
                "title": finding.title,
                "severity": finding.severity.value,
                "target": item.target,
                "affected_hosts": finding.affected_hosts,
                "evidence": finding.evidence,
                "hash": finding.hash,
            },
            source_command,
            quality_gate=quality_gate,
            quiet=quiet,
        ):
            findings.append(finding)
            written_finding_pairs.append((item, finding))

    new, duplicates = (
        merge_and_save_findings(engagement, findings) if findings else ([], [])
    )
    for extracted_finding, persisted_finding in written_finding_pairs:
        entry = {
            "message": extracted_finding.title,
            "date": now_iso(),
            "host": extracted_finding.target,
            "tags": ["ghostlog", "finding", extracted_finding.severity],
            "linked_finding_hash": persisted_finding.hash,
        }
        store.add_log(entry)
        append_timeline_entry(engagement.notes_dir, entry)
        if extracted_finding.target:
            path = host_note_path(engagement.notes_dir, extracted_finding.target)
            if not path.exists():
                atomic_write_text(path, f"# {extracted_finding.target}\n\n## Notes\n")
            append_to_host_note(
                engagement.notes_dir,
                extracted_finding.target,
                f"Ghost Log: {extracted_finding.title} - {extracted_finding.evidence}",
            )
    linked_hash = findings[0].hash if findings else None
    for note in [*extraction.notes, *extraction.log_entries]:
        entry = {
            "message": note,
            "date": now_iso(),
            "host": None,
            "tags": ["ghostlog"],
            "linked_finding_hash": linked_hash,
        }
        store.add_log(entry)
        append_timeline_entry(engagement.notes_dir, entry)
    return len(new), len(duplicates)


def _should_write_item(
    store: WorkspaceStore,
    item_type: str,
    payload: dict[str, Any],
    source_command: str | None,
    *,
    quality_gate: bool,
    quiet: bool,
) -> bool:
    if not quality_gate:
        _record_quality(store, written=1, confidence=1.0)
        return True

    gated = _quality_gate(item_type, payload)
    if gated.confidence >= QUALITY_THRESHOLD_WRITE:
        if gated.quality == ExtractionConfidence.MEDIUM:
            payload.setdefault("tags", []).append("quality:medium")
        _record_quality(store, written=1, confidence=gated.confidence)
        return True
    if gated.confidence >= QUALITY_THRESHOLD_QUEUE:
        _queue_for_review(store, item_type, payload, gated, source_command)
        _record_quality(store, queued=1, confidence=gated.confidence)
        if not quiet:
            label = payload.get("username") or payload.get("title") or item_type
            print(
                f"[ghost] Queued low-confidence {item_type} "
                f"({gated.confidence:.0%}): {label} — run: pentnote log --review"
            )
        return False

    _record_quality(store, rejected=1, confidence=gated.confidence)
    if not quiet:
        label = payload.get("username") or payload.get("title") or item_type
        print(f"[ghost] Rejected {item_type} ({gated.confidence:.0%}): {label}")
    return False


def _quality_gate(item_type: str, payload: dict[str, Any]) -> QualityGatedExtraction:
    score = (
        _validate_credential(payload)
        if item_type == "credential"
        else _validate_finding(payload)
    )
    notes = _validation_notes(item_type, payload)
    return QualityGatedExtraction(
        raw_extraction=payload,
        confidence=score,
        quality=_quality_for_score(score),
        validation_notes=notes,
    )


def _quality_for_score(score: float) -> ExtractionConfidence:
    if score > 0.8:
        return ExtractionConfidence.HIGH
    if score >= 0.5:
        return ExtractionConfidence.MEDIUM
    return ExtractionConfidence.LOW


def _queue_for_review(
    store: WorkspaceStore,
    item_type: str,
    payload: dict[str, Any],
    gated: QualityGatedExtraction,
    source_command: str | None,
) -> None:
    data = store.load()
    created_at = datetime.now(UTC).replace(microsecond=0)
    queue_item = {
        "id": _review_item_id(item_type, payload, created_at.isoformat()),
        "type": item_type,
        "payload": payload,
        "confidence": round(gated.confidence, 2),
        "quality": gated.quality.value,
        "validation_notes": gated.validation_notes,
        "source_command": source_command[:200] if source_command else None,
        "created_at": created_at.isoformat(),
        "expires_at": (created_at + timedelta(days=REVIEW_EXPIRY_DAYS)).isoformat(),
    }
    data.setdefault("pending_review", []).append(queue_item)
    store.save(data)


def _record_quality(
    store: WorkspaceStore,
    *,
    written: int = 0,
    queued: int = 0,
    rejected: int = 0,
    confidence: float,
) -> None:
    data = store.load()
    stats = {
        "written": 0,
        "queued": 0,
        "rejected": 0,
        "confidence_total": 0.0,
        "confidence_count": 0,
        **dict(data.get("quality_stats", {})),
    }
    stats["written"] = int(stats.get("written") or 0) + written
    stats["queued"] = int(stats.get("queued") or 0) + queued
    stats["rejected"] = int(stats.get("rejected") or 0) + rejected
    stats["confidence_total"] = float(stats.get("confidence_total") or 0.0) + confidence
    stats["confidence_count"] = int(stats.get("confidence_count") or 0) + 1
    data["quality_stats"] = stats
    store.save(data)


def _review_item_id(item_type: str, payload: dict[str, Any], created_at: str) -> str:
    serialized = repr(sorted(payload.items()))
    return hashlib.sha256(
        f"{item_type}|{serialized}|{created_at}".encode()
    ).hexdigest()[:12]


def _validate_credential(cred: dict[str, Any]) -> float:
    """Score confidence that an extracted credential is real."""

    score = 0.0
    username = str(cred.get("username") or "")
    if username and len(username) > 1:
        score += 0.3

    secret = str(cred.get("secret") or "")
    if re.fullmatch(r"[0-9a-fA-F]{32}", secret) or re.fullmatch(
        r"[0-9a-fA-F]{64}", secret
    ):
        score += 0.4
    elif len(secret) > 6:
        score += 0.2

    host = str(cred.get("source_host") or cred.get("target") or "")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += 0.3
    return min(1.0, score)


def _validate_finding(finding: dict[str, Any]) -> float:
    """Score confidence that an extracted finding is real."""

    score = 0.0
    title = str(finding.get("title") or "")
    if len(title) > 5:
        score += 0.3
    evidence = str(finding.get("evidence") or "")
    if evidence:
        score += 0.4
    hosts = finding.get("affected_hosts") or []
    target = finding.get("target")
    if hosts or target:
        score += 0.3
    if not evidence:
        score = min(score, 0.5)
    return min(1.0, score)


def _validation_notes(item_type: str, payload: dict[str, Any]) -> list[str]:
    notes = []
    if item_type == "credential":
        if not payload.get("username"):
            notes.append("missing username")
        if not payload.get("secret"):
            notes.append("missing secret")
        if not (payload.get("source_host") or payload.get("target")):
            notes.append("missing source host")
    else:
        if not payload.get("title"):
            notes.append("missing title")
        if not payload.get("evidence"):
            notes.append("missing evidence")
        if not (payload.get("affected_hosts") or payload.get("target")):
            notes.append("missing affected host")
    return notes


def _severity(value: str) -> Severity:
    try:
        return Severity(value.casefold())
    except ValueError:
        return Severity.INFO


def _finding_hash(title: str, evidence: str, hosts: list[str]) -> str:
    payload = "|".join([title.casefold(), evidence.casefold(), ",".join(sorted(hosts))])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

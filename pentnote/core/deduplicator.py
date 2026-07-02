"""SHA256-based finding deduplication."""

from __future__ import annotations

import hashlib

from pentnote.core.models import PentNoteModel
from pentnote.models import Finding


class DedupeResult(PentNoteModel):
    """Result of merging incoming findings into existing findings."""

    merged: list[Finding]
    new: list[Finding]
    duplicates: list[Finding]


def finding_hash(tool: str, host: str | None, title: str) -> str:
    """Return the canonical SHA256 deduplication key."""

    payload = "|".join(
        [
            tool.casefold().strip(),
            (host or "").casefold().strip(),
            title.casefold().strip(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def merge_findings(existing: list[Finding], incoming: list[Finding]) -> DedupeResult:
    """Merge findings by their canonical hash."""

    seen = {finding.hash for finding in existing}
    merged = list(existing)
    new: list[Finding] = []
    duplicates: list[Finding] = []

    for finding in incoming:
        if finding.hash in seen:
            duplicates.append(finding)
            continue
        seen.add(finding.hash)
        merged.append(finding)
        new.append(finding)

    return DedupeResult(merged=merged, new=new, duplicates=duplicates)

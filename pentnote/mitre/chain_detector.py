"""MITRE ATT&CK chain detection."""

from __future__ import annotations

import json
from collections import defaultdict
from importlib import resources

from pentnote.core.models import PentNoteModel
from pentnote.models import Finding


class DetectedChain(PentNoteModel):
    """Detected attack-chain summary."""

    name: str
    label: str
    severity: str
    required_ttps: list[str]
    optional_ttps: list[str]
    matched_ttps: list[str]
    message: str


def detect_chains(findings: list[Finding]) -> list[DetectedChain]:
    """Detect complete attack chains within shared host or domain scopes."""

    detected: list[DetectedChain] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for scope_findings in _findings_by_scope(findings).values():
        observed = _observed_ttps(scope_findings)
        for name, definition in _load_chain_definitions().items():
            required = set(definition["required_ttps"])
            if not required <= observed:
                continue
            optional = set(definition["optional_ttps"])
            matched = tuple(sorted(required | (optional & observed)))
            key = (name, matched)
            if key in seen:
                continue
            seen.add(key)
            detected.append(
                DetectedChain(
                    name=name,
                    label=definition["label"],
                    severity=definition["severity"],
                    required_ttps=definition["required_ttps"],
                    optional_ttps=definition["optional_ttps"],
                    matched_ttps=list(matched),
                    message=definition["message"],
                )
            )
    return detected


def apply_chain_membership(findings: list[Finding]) -> list[DetectedChain]:
    """Mark findings with detected chain labels when they participate."""

    detected: list[DetectedChain] = []
    for scope_findings in _findings_by_scope(findings).values():
        scope_chains = detect_chains(scope_findings)
        detected.extend(scope_chains)
        for chain in scope_chains:
            matched = set(chain.matched_ttps)
            for finding in scope_findings:
                finding_ttps = {match.technique_id for match in finding.mitre_matches}
                if matched & finding_ttps:
                    finding.chain_member = chain.label
    return detected


def _findings_by_scope(findings: list[Finding]) -> dict[str, list[Finding]]:
    by_scope: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        scopes = finding.affected_hosts or ["global"]
        for scope in scopes:
            by_scope[_scope_key(scope)].append(finding)
    return by_scope


def _scope_key(value: str) -> str:
    parts = value.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return ".".join(parts[:3]) + ".0/24"
    return value.casefold()


def _observed_ttps(findings: list[Finding]) -> set[str]:
    return {
        match.technique_id for finding in findings for match in finding.mitre_matches
    }


def _load_chain_definitions() -> dict[str, dict[str, object]]:
    with (
        resources.files("pentnote.mitre.data")
        .joinpath("chains.json")
        .open(encoding="utf-8") as handle
    ):
        return json.load(handle)

"""Certipy AD CS parser."""

from __future__ import annotations

import re
from collections.abc import Iterable

from pentnote.core.deduplicator import finding_hash
from pentnote.models import DomainObject, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser


class CertipyParser(AbstractParser):
    """Parse Certipy AD CS enumeration output."""

    tool_name = "certipy"
    aliases = ("certipy-ad",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content looks like Certipy output."""

        clean = self.clean(content)
        score = 0.0
        if "Certipy v" in clean:
            score += 0.35
        if "Certificate Authorities" in clean:
            score += 0.25
        if "Certificate Templates" in clean:
            score += 0.25
        if "ESC" in clean and "Vulnerabilities" in clean:
            score += 0.15
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Certipy output into AD CS domain objects and findings."""

        clean = self.clean(content)
        ca_blocks = _section_blocks(clean, "Certificate Authorities")
        template_blocks = _section_blocks(clean, "Certificate Templates")

        objects = [
            _domain_object("certificate_authority", _fields(block), block)
            for block in ca_blocks
        ]
        objects.extend(
            _domain_object("certificate_template", _fields(block), block)
            for block in template_blocks
        )

        ca_name = _first_value(_fields(block).get("CA Name") for block in ca_blocks)
        dns_name = _first_value(_fields(block).get("DNS Name") for block in ca_blocks)
        affected_host = dns_name or ca_name or "adcs"

        findings: list[Finding] = []
        for block in template_blocks:
            fields = _fields(block)
            template_name = fields.get("Template Name") or fields.get("Display Name")
            if not template_name:
                continue
            for esc_id, description in _vulnerabilities(block):
                title = f"AD CS {esc_id} on Template {template_name}"
                evidence = _compact_evidence(block, esc_id, description)
                findings.append(
                    Finding(
                        title=title,
                        severity=_severity(esc_id),
                        mitre_matches=[
                            MitreMatch(
                                "T1649",
                                "Steal or Forge Authentication Certificates",
                                "Credential Access",
                                0.85,
                                "rule",
                            )
                        ],
                        affected_hosts=[affected_host],
                        evidence=evidence,
                        next_steps=[
                            "Confirm the template is enabled on the CA.",
                            "Validate whether the enrollee principal can request the template.",
                            "Review linked issuance policy or group impact before exploitation.",
                        ],
                        defenses=[],
                        chain_member=None,
                        hash=finding_hash(self.tool_name, affected_host, title),
                    )
                )

        partial = "Enumeration output:" in clean and not (ca_blocks or template_blocks)
        return ParsedResult(self.tool_name, partial, [], [], findings, objects, content)


def _section_blocks(content: str, heading: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(heading)}\s*$", content)
    if not match:
        return []
    next_heading = re.search(
        r"(?m)^(?:Certificate Authorities|Certificate Templates)\s*$",
        content[match.end() :],
    )
    section = (
        content[match.end() :]
        if next_heading is None
        else content[match.end() : match.end() + next_heading.start()]
    )
    blocks = re.split(r"(?m)^\s{2}\d+\s*$", section)
    return [block.strip("\n") for block in blocks if block.strip()]


def _fields(block: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current_key: str | None = None
    for raw_line in block.splitlines():
        line = raw_line.rstrip()
        match = re.match(r"^\s{4,}([^:\[][^:]+?)\s+:\s*(.*)$", line)
        if match:
            current_key = match.group(1).strip()
            fields[current_key] = match.group(2).strip()
            continue
        if current_key and re.match(r"^\s{8,}\S", line):
            fields[current_key] = f"{fields[current_key]}\n{line.strip()}".strip()
    return fields


def _domain_object(
    object_type: str, fields: dict[str, str], evidence: str
) -> DomainObject:
    name = (
        fields.get("CA Name")
        or fields.get("Template Name")
        or fields.get("Display Name")
        or "unknown"
    )
    domain = _domain_from_fields(fields)
    properties = dict(fields)
    properties["evidence"] = evidence.strip()
    return DomainObject(
        name=name, object_type=object_type, domain=domain, properties=properties
    )


def _domain_from_fields(fields: dict[str, str]) -> str:
    for value in (fields.get("DNS Name"), fields.get("Certificate Subject")):
        if not value:
            continue
        dc_parts = re.findall(r"\bDC=([^,\s]+)", value, flags=re.IGNORECASE)
        if dc_parts:
            return ".".join(part.lower() for part in dc_parts)
        if "." in value:
            return ".".join(value.split(".")[-2:])
    return ""


def _vulnerabilities(block: str) -> list[tuple[str, str]]:
    return [
        (match.group(1), match.group(2).strip())
        for match in re.finditer(r"(?m)^\s+(ESC\d+)\s+:\s+(.+)$", block)
    ]


def _severity(esc_id: str) -> Severity:
    if esc_id in {"ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7"}:
        return Severity.CRITICAL
    return Severity.HIGH


def _compact_evidence(block: str, esc_id: str, description: str) -> str:
    interesting = (
        "Template Name",
        "Display Name",
        "Certificate Authorities",
        "Enabled",
        "Client Authentication",
        "Enrollment Agent",
        "Any Purpose",
        "Enrollee Supplies Subject",
        "Issuance Policies",
        "Linked Groups",
        "Enrollment Rights",
        "User Enrollable Principals",
    )
    lines = []
    for line in block.splitlines():
        if any(item in line for item in interesting):
            lines.append(line.rstrip())
    lines.append(f"      {esc_id:<34}: {description}")
    return "\n".join(lines)


def _first_value(values: Iterable[str | None]) -> str | None:
    for value in values:
        if value:
            return value
    return None

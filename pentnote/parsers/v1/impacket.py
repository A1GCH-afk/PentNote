"""Impacket parser implementations."""

from __future__ import annotations

import re

from pyparsing import (
    CharsNotIn,
    Literal,
    ParseException,
    StringEnd,
    Suppress,
    Word,
    alphanums,
    hexnums,
    nums,
)

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_HASH_LINE = (
    CharsNotIn(":\n")("principal")
    + Suppress(":")
    + Word(nums)("rid")
    + Suppress(":")
    + Word(hexnums, exact=32)("lm_hash")
    + Suppress(":")
    + Word(hexnums, exact=32)("nt_hash")
    + Literal(":::").suppress()
    + StringEnd()
)
_KERBEROS_LINE = (
    CharsNotIn(":\n")("principal")
    + Suppress(":")
    + Word(alphanums + "-")("etype")
    + Suppress(":")
    + Word(hexnums, min=32, max=128)("key")
    + StringEnd()
)


class SecretsDumpParser(AbstractParser):
    """Parse Impacket secretsdump credential output."""

    tool_name = "impacket-secretsdump"
    aliases = ("secretsdump", "impacket")
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Impacket secretsdump output."""

        clean = self.clean(content)
        lowered = clean.casefold()
        score = 0.0
        if "impacket" in lowered:
            score += 0.25
        if "dumping local sam hashes" in lowered or "secretsdump" in lowered:
            score += 0.35
        hash_lines = sum(
            1 for line in clean.splitlines() if _parse_hash_line(line.strip())
        )
        if hash_lines:
            score += min(0.4, hash_lines * 0.2)
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse secretsdump output into credentials and findings."""

        clean = self.clean(content)
        credentials: list[Credential] = []
        findings: list[Finding] = []
        source_host = _extract_source_host(clean) or "unknown"
        in_credential_section = False
        partial = False

        for line in clean.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lowered = stripped.casefold()
            if "dumping local sam hashes" in lowered or "dumping cached" in lowered:
                in_credential_section = True
                continue
            if stripped.startswith("[*]"):
                if "cleaning up" in lowered:
                    in_credential_section = False
                continue

            secret = _parse_hash_line(stripped) or _parse_kerberos_line(stripped)
            if secret is None:
                if in_credential_section:
                    partial = True
                continue

            username, domain = _principal_parts(secret["principal"])
            secret_type = secret["secret_type"]
            secret_value = secret["secret"]
            credentials.append(
                Credential(
                    username=username,
                    secret=secret_value,
                    secret_type=secret_type,
                    source_host=source_host,
                    domain=domain,
                )
            )
            title = f"{secret_type.upper()} credential material found for {username}"
            findings.append(
                Finding(
                    title=title,
                    severity=(
                        Severity.CRITICAL
                        if username.casefold() == "administrator"
                        else Severity.HIGH
                    ),
                    mitre_matches=[],
                    affected_hosts=[source_host],
                    evidence=stripped,
                    next_steps=["Validate credential scope and rotation requirements."],
                    defenses=[],
                    chain_member=None,
                    hash=finding_hash(self.tool_name, source_host, title),
                )
            )

        return ParsedResult(
            tool=self.tool_name,
            partial=partial,
            hosts=[],
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _parse_hash_line(line: str) -> dict[str, str] | None:
    try:
        parsed = _HASH_LINE.parse_string(line, parse_all=True)
    except ParseException:
        return None
    return {
        "principal": parsed["principal"],
        "secret": parsed["nt_hash"],
        "secret_type": "ntlm",
    }


def _parse_kerberos_line(line: str) -> dict[str, str] | None:
    try:
        parsed = _KERBEROS_LINE.parse_string(line, parse_all=True)
    except ParseException:
        return None
    if not parsed["etype"].startswith("aes"):
        return None
    return {
        "principal": parsed["principal"],
        "secret": parsed["key"],
        "secret_type": "kerberos",
    }


def _principal_parts(principal: str) -> tuple[str, str | None]:
    if "\\" not in principal:
        return principal, None
    domain, username = principal.split("\\", 1)
    return username, domain


def _extract_source_host(content: str) -> str | None:
    patterns = (
        r"(?i)target(?:\s+system)?\s*[:=]\s*([A-Za-z0-9_.-]+)",
        r"(?i)connecting\s+to\s+([A-Za-z0-9_.-]+)",
        r"(?i)against\s+([A-Za-z0-9_.-]+)",
        r"(?m)^Impacket.*?@([A-Za-z0-9_.-]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, content)
        if match:
            return match.group(1).strip()
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
    return match.group(0) if match else None

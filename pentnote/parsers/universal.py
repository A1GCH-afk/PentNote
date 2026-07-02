"""Universal fallback parser for unrecognized text output."""

from __future__ import annotations

from pyparsing import (
    CaselessKeyword,
    Combine,
    FollowedBy,
    Literal,
    OneOrMore,
    Optional,
    Suppress,
    Word,
    alphanums,
    alphas,
    hexnums,
    nums,
    one_of,
)

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, Host, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

MIN_INDICATORS_TO_EMIT_FINDING = 3

_OCTET = Word(nums, min=1, max=3)
_IPV4 = Combine(_OCTET + "." + _OCTET + "." + _OCTET + "." + _OCTET)
_PORT_SLASH = (
    Word(nums, min=1, max=5)("port") + Suppress("/") + Word(alphas)("protocol")
)
_PORT_WORD = (
    CaselessKeyword("port").suppress()
    + Optional(Suppress(":"))
    + Word(nums, min=1, max=5)("port")
)
_HASH = Word(hexnums, exact=32) | Word(hexnums, exact=40) | Word(hexnums, exact=64)
_CVE = Combine(
    CaselessKeyword("CVE")
    + Literal("-")
    + Word(nums, exact=4)
    + Literal("-")
    + Word(nums, min=4, max=7)
)
_USERNAME = (
    one_of("user username account login", caseless=True).suppress()
    + Optional(Suppress(":"))
    + Word(alphanums + "._-$\\")("username")
)
_URL = Combine(
    one_of("http https", caseless=True)
    + Literal("://")
    + OneOrMore(Word(alphanums + "-._~:/?#[]@!$&'()*+,;=%"))
    + FollowedBy(Optional(Word(" \t\r\n")))
)


class UniversalParser(AbstractParser):
    """Extract common indicators from arbitrary text."""

    tool_name = "universal"
    aliases = ("generic", "fallback")
    supported_extensions = (".txt", ".log", ".out")

    def can_parse(self, content: str) -> float:
        """Return fallback confidence for text containing common indicators."""

        if not content.strip():
            return 0.0
        extractor_hits = sum(
            bool(values)
            for values in (
                _scan(_IPV4, content),
                _scan(_PORT_SLASH, content) or _scan(_PORT_WORD, content),
                _scan(_HASH, content),
                _scan(_CVE, content),
                _scan(_USERNAME, content),
                _scan(_URL, content),
            )
        )
        return min(0.6, 0.05 + (extractor_hits * 0.1))

    def parse(self, content: str) -> ParsedResult:
        """Extract universal indicators as structured findings."""

        clean = self.clean(content)
        ipv4s = _unique_ips(_scan(_IPV4, clean))
        ports = _extract_ports(clean)
        hashes = _unique_text(_scan(_HASH, clean))
        cves = _unique_text(_scan(_CVE, clean))
        usernames = _unique_text(_scan(_USERNAME, clean, "username"))
        urls = _unique_text(_scan(_URL, clean))

        indicator_count = sum(
            len(values) for values in (ipv4s, ports, hashes, cves, usernames, urls)
        )
        if indicator_count < MIN_INDICATORS_TO_EMIT_FINDING:
            return ParsedResult(
                tool=self.tool_name,
                partial=False,
                hosts=[],
                credentials=[],
                findings=[],
                domain_objects=[],
                raw_text=content,
            )

        findings = [
            *_indicator_findings(
                self.tool_name, "IPv4 address observed", ipv4s, Severity.INFO
            ),
            *_indicator_findings(
                self.tool_name, "Port reference observed", ports, Severity.INFO
            ),
            *_indicator_findings(
                self.tool_name, "Hash material observed", hashes, Severity.HIGH
            ),
            *_indicator_findings(
                self.tool_name, "CVE reference observed", cves, Severity.HIGH
            ),
            *_indicator_findings(
                self.tool_name, "Username observed", usernames, Severity.LOW
            ),
            *_indicator_findings(self.tool_name, "URL observed", urls, Severity.INFO),
        ]
        hosts = [Host(ip=ip, hostname=None, os=None, ports=[], tags=[]) for ip in ipv4s]
        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=hosts,
            credentials=[],
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _scan(parser, content: str, field: str | None = None) -> list[str]:
    values: list[str] = []
    for tokens, _, _ in parser.scan_string(content):
        if field:
            values.append(tokens[field])
        else:
            values.append(tokens[0])
    return values


def _extract_ports(content: str) -> list[str]:
    values = [tokens["port"] for tokens, _, _ in _PORT_SLASH.scan_string(content)]
    values.extend(tokens["port"] for tokens, _, _ in _PORT_WORD.scan_string(content))
    return _unique_text(values)


def _unique_text(values: list[str]) -> list[str]:
    unique: list[str] = []
    for value in values:
        cleaned = str(value).strip(".,;)]}")
        if cleaned and cleaned not in unique:
            unique.append(cleaned)
    return unique


def _unique_ips(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen_ips: set[str] = set()
    for value in values:
        cleaned = str(value).strip(".,;)]}")
        if cleaned.startswith("0.") or cleaned in seen_ips:
            continue
        seen_ips.add(cleaned)
        unique.append(cleaned)
    return unique


def _indicator_findings(
    tool: str,
    title: str,
    values: list[str],
    severity: Severity,
) -> list[Finding]:
    findings: list[Finding] = []
    for value in values:
        finding_title = f"{title}: {value}"
        findings.append(
            Finding(
                title=finding_title,
                severity=severity,
                mitre_matches=[],
                affected_hosts=[value] if title.startswith("IPv4") else [],
                evidence=value,
                next_steps=["Correlate this indicator with engagement scope."],
                defenses=[],
                chain_member=None,
                hash=finding_hash(
                    tool,
                    value if title.startswith("IPv4") else "",
                    finding_title,
                ),
            )
        )
    return findings

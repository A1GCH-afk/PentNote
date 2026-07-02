"""Example parser plugin for fictional MyScanner output."""

from __future__ import annotations

from pentnote.core.deduplicator import finding_hash
from pentnote.core.models import (
    Credential,
    Finding,
    Host,
    MitreMatch,
    ParsedResult,
    Severity,
)
from pentnote.parsers.base import AbstractParser


class MyScannerParser(AbstractParser):
    """Parse fictional MyScanner output."""

    tool_name = "myscanner"
    aliases = ("my-scan", "mscan")
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        signals = ("[MyScanner]", "Scan complete")
        hits = sum(1 for signal in signals if signal in content)
        return min(1.0, hits * 0.5)

    def parse(self, content: str) -> ParsedResult:
        hosts: list[Host] = []
        credentials: list[Credential] = []
        findings: list[Finding] = []
        partial = False

        for line in self.clean(content).splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "HOST" and len(parts) >= 4:
                hosts.append(Host(ip=parts[1], hostname=parts[2], os=parts[3]))
            elif parts[0] == "CRED" and len(parts) >= 2:
                parsed = _parse_credential(parts[1])
                if parsed is None:
                    partial = True
                    continue
                username, secret, host = parsed
                credentials.append(
                    Credential(
                        username=username,
                        secret=secret,
                        secret_type="plaintext",
                        source_host=host,
                    )
                )
            elif parts[0] == "VULN" and len(parts) >= 3:
                host = parts[1]
                description = " ".join(parts[2:])
                title = f"MyScanner finding: {description}"
                findings.append(
                    Finding(
                        title=title,
                        severity=Severity.HIGH,
                        mitre_matches=[
                            MitreMatch(
                                technique_id="T1190",
                                technique_name="Exploit Public-Facing Application",
                                tactic="Initial Access",
                                confidence=0.8,
                                source="rule",
                            )
                        ],
                        affected_hosts=[host],
                        evidence=line,
                        next_steps=["Verify the finding manually."],
                        defenses=[],
                        hash=finding_hash(self.tool_name, host, title),
                    )
                )
        return ParsedResult(
            tool=self.tool_name,
            partial=partial,
            hosts=hosts,
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _parse_credential(value: str) -> tuple[str, str, str] | None:
    if ":" not in value or "@" not in value:
        return None
    username, rest = value.split(":", 1)
    secret, host = rest.rsplit("@", 1)
    if not username or not secret or not host:
        return None
    return username, secret, host

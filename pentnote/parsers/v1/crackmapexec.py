"""CrackMapExec and NetExec parser."""

from __future__ import annotations

import re

from pyparsing import (
    Combine,
    ParseException,
    ParserElement,
    Word,
    alphanums,
    nums,
    printables,
    restOfLine,
)
from pyparsing import Optional as PPOptional

from pentnote.core.deduplicator import finding_hash
from pentnote.models import (
    Credential,
    Finding,
    Host,
    ParsedResult,
    Port,
    Severity,
    WorkspaceLoot,
)
from pentnote.parsers.base import AbstractParser

ParserElement.set_default_whitespace_chars(" \t")

_OCTET = Word(nums, min=1, max=3)
_IPV4 = Combine(_OCTET + "." + _OCTET + "." + _OCTET + "." + _OCTET)
_LINE = (
    Word(alphanums + "_-")("protocol")
    + _IPV4("host")
    + Word(nums)("port")
    + Word(printables)("name")
    + PPOptional(restOfLine("message"), default="")
)
AV_ENUM_PATTERN = re.compile(r"\[\*\]\s+(.+?)\s+\((enabled|disabled)\)", re.I)

# nxc emits "<label> saved to: <path>" (and "saved to <path>") whenever a module
# writes an artifact to disk (--generate-krb5-file, and --sam/--lsa/--ntds dumps).
# The path is actionable loot; historically these lines were parsed and silently
# discarded because they are neither a credential, a finding, nor a host field.
ARTIFACT_SAVED_PATTERN = re.compile(r"saved to:?\s+(?P<path>\S+)", re.I)

# "[+]" success lines that carry no artifact/credential but are benign follow-up
# guidance nxc prints after a module runs (e.g. how to use a generated krb5 conf).
# These are recognized-and-ignored, not counted as unrecognized output.
_BENIGN_SUCCESS_MARKERS = (
    "run the following command",
    "export krb5_config",
)


class CrackMapExecParser(AbstractParser):
    """Parse CrackMapExec and NetExec text output."""

    tool_name = "crackmapexec"
    aliases = ("cme", "netexec", "nxc")
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is CME/NetExec output."""

        clean = self.clean(content)
        lines = [line for line in clean.splitlines() if line.strip()]
        if not lines:
            return 0.0

        parsed = [self._parse_line(line) for line in lines]
        parsed_count = sum(item is not None for item in parsed)
        score = min(0.8, parsed_count / len(lines))
        lowered = clean.casefold()
        if any(token in lowered for token in ("pwn3d", "signing:", "smbv1:")):
            score += 0.2
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse CME/NetExec output into structured objects."""

        clean = self.clean(content)
        hosts: dict[str, Host] = {}
        credentials: list[Credential] = []
        findings: list[Finding] = []
        loot: list[WorkspaceLoot] = []
        unrecognized: list[tuple[str, str]] = []
        non_empty = 0
        matched_count = 0

        for line in clean.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            non_empty += 1
            parsed = self._parse_line(stripped)
            if parsed is None:
                continue
            matched_count += 1

            protocol = parsed["protocol"].casefold()
            host = parsed["host"]
            port_number = int(parsed["port"])
            target_name = parsed["name"]
            message = parsed["message"].strip()
            host_obj = hosts.setdefault(
                host,
                Host(
                    ip=host,
                    hostname=target_name,
                    os=_extract_os(message),
                    ports=[],
                    tags=[],
                ),
            )
            _merge_port(host_obj, port_number, protocol, protocol, "open")
            _merge_tag(host_obj, protocol)

            av_product = _parse_av_enum(message)
            if av_product is not None:
                product, enabled = av_product
                _merge_av_product(host_obj, product)
                _merge_tag(host_obj, f"av:{_slugify(product)}")
                if enabled:
                    _merge_tag(host_obj, "av-active")

            success_consumed = False

            credential = self._credential_from_message(message, host)
            if credential is not None:
                credentials.append(credential)
                title = (
                    "Administrative access confirmed"
                    if "pwn3d" in message.casefold()
                    else "Valid credential identified"
                )
                findings.append(
                    _finding(
                        tool=self.tool_name,
                        host=host,
                        title=title,
                        severity=Severity.HIGH,
                        evidence=stripped,
                        next_steps=["Validate privilege level and reachable hosts."],
                    )
                )
                success_consumed = True

            artifact = _artifact_from_message(message, host)
            if artifact is not None:
                loot.append(artifact)
                success_consumed = True

            if _smb_signing_disabled(message):
                findings.append(
                    _finding(
                        tool=self.tool_name,
                        host=host,
                        title="SMB signing disabled",
                        severity=Severity.HIGH,
                        evidence=stripped,
                        next_steps=["Test SMB relay feasibility in scope."],
                    )
                )

            if _is_unrecognized_success(message, success_consumed):
                unrecognized.append((host, stripped))

        if unrecognized:
            findings.append(_unrecognized_finding(self.tool_name, unrecognized))

        return ParsedResult(
            tool=self.tool_name,
            partial=non_empty > matched_count or bool(unrecognized),
            hosts=list(hosts.values()),
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            loot=loot,
            raw_text=content,
        )

    def _parse_line(self, line: str) -> dict[str, str] | None:
        try:
            parsed = _LINE.parse_string(line, parse_all=True)
        except ParseException:
            return None
        return {
            "protocol": parsed["protocol"],
            "host": parsed["host"],
            "port": parsed["port"],
            "name": parsed["name"],
            "message": parsed["message"],
        }

    def _credential_from_message(self, message: str, host: str) -> Credential | None:
        parsed = _parse_success(message)
        if parsed is None:
            return None
        domain, username, secret = parsed
        return Credential(
            username=username,
            secret=secret,
            secret_type=(
                "ntlm" if re.fullmatch(r"[0-9a-fA-F]{32}", secret) else "plaintext"
            ),
            source_host=host,
            domain=domain,
        )


def _parse_success(message: str) -> tuple[str | None, str, str] | None:
    marker = "[+]"
    if marker not in message:
        return None
    identity = message.split(marker, 1)[1].strip().split()[0]
    if ":" not in identity:
        return None
    principal, secret = identity.split(":", 1)
    if "\\" in principal:
        domain, username = principal.split("\\", 1)
    else:
        domain, username = None, principal
    return domain, username, secret


def _artifact_from_message(message: str, host: str) -> WorkspaceLoot | None:
    """Capture a generated-artifact path from an nxc '... saved to: <path>' line."""

    match = ARTIFACT_SAVED_PATTERN.search(message)
    if match is None:
        return None
    path = match.group("path").strip().rstrip(".,")
    if not path:
        return None
    label = _artifact_label(message)
    return WorkspaceLoot(
        type="file",
        host=host,
        value=path,
        path=path,
        notes=f"{label} (crackmapexec)".strip(),
        tags=["crackmapexec", "artifact"],
    )


def _artifact_label(message: str) -> str:
    """Return the human label preceding 'saved to' (e.g. 'krb5 conf')."""

    lowered = message.casefold()
    index = lowered.find("saved to")
    prefix = message[:index] if index != -1 else message
    prefix = prefix.replace("[+]", "").replace("[*]", "").strip().rstrip(",:;")
    return prefix or "artifact"


def _is_unrecognized_success(message: str, consumed: bool) -> bool:
    """Flag an nxc success line whose payload was not mapped to any record.

    Only "[+]" success markers are tracked: they mean a module produced an
    actionable result. If nothing consumed it and it is not benign follow-up
    guidance, the content would otherwise be silently dropped.
    """

    if consumed or "[+]" not in message:
        return False
    lowered = message.casefold()
    return not any(marker in lowered for marker in _BENIGN_SUCCESS_MARKERS)


def _unrecognized_finding(tool: str, unrecognized: list[tuple[str, str]]) -> Finding:
    hosts = sorted({host for host, _ in unrecognized})
    evidence = "\n".join(f"{host}: {line}" for host, line in unrecognized[:20])
    return Finding(
        title="Unrecognized crackmapexec output",
        severity=Severity.INFO,
        mitre_matches=[],
        affected_hosts=hosts,
        evidence=evidence,
        next_steps=[
            "Review the raw capture; these nxc success lines were not mapped "
            "to a host, credential, finding, or loot record."
        ],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, "", "Unrecognized crackmapexec output"),
    )


def _extract_os(message: str) -> str | None:
    lowered = message.casefold()
    if "windows" not in lowered:
        return None
    start = lowered.find("windows")
    end = message.find("(", start)
    return message[start:end].strip() if end != -1 else message[start:].strip()


def _smb_signing_disabled(message: str) -> bool:
    lowered = message.casefold().replace(" ", "")
    return "signing:false" in lowered or "signing:disabled" in lowered


def _merge_port(
    host: Host,
    number: int,
    protocol: str,
    service: str,
    state: str,
) -> None:
    if any(port.number == number and port.protocol == protocol for port in host.ports):
        return
    host.ports.append(Port(number, protocol, service, None, state))


def _merge_tag(host: Host, tag: str) -> None:
    if tag not in host.tags:
        host.tags.append(tag)


def _merge_av_product(host: Host, product: str) -> None:
    if product not in host.av_products:
        host.av_products.append(product)


def _parse_av_enum(message: str) -> tuple[str, bool] | None:
    match = AV_ENUM_PATTERN.search(message)
    if match is None:
        return None
    product = match.group(1).strip()
    enabled = match.group(2).casefold() == "enabled"
    return product, enabled


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug or "unknown"


def _finding(
    *,
    tool: str,
    host: str,
    title: str,
    severity: Severity,
    evidence: str,
    next_steps: list[str],
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[],
        affected_hosts=[host],
        evidence=evidence,
        next_steps=next_steps,
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, host, title),
    )

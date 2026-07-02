"""Build target context for operator payload suggestions."""

from __future__ import annotations

from pathlib import Path

from pentnote.core.engagement import Engagement, load_findings, load_local_config
from pentnote.core.models import (
    DefenseProfile,
    Finding,
    Host,
    PayloadContext,
    WorkspaceCredential,
)
from pentnote.workspace.store import WorkspaceStore, host_note_path

AV_INDICATORS = {
    "defender": ["Windows Defender", "MsMpEng"],
    "crowdstrike": ["CrowdStrike", "CSFalcon", "csagent"],
    "sentinelone": ["SentinelOne", "SentinelAgent"],
    "cylance": ["Cylance", "CylanceSvc"],
    "carbon_black": ["CarbonBlack", "cb.exe"],
    "sophos": ["Sophos", "SavService"],
    "eset": ["ESET", "ekrn.exe"],
}
PRODUCT_LABELS = {
    "defender": "Windows Defender",
    "crowdstrike": "CrowdStrike",
    "sentinelone": "SentinelOne",
    "cylance": "Cylance",
    "carbon_black": "CarbonBlack",
    "sophos": "Sophos",
    "eset": "ESET",
}
EDR_PRODUCTS = {"crowdstrike", "sentinelone", "cylance", "carbon_black"}


def build_contexts(
    engagement: Engagement,
    *,
    host: str | None = None,
    credential_user: str | None = None,
) -> list[PayloadContext]:
    """Build payload contexts from host notes, credentials, and local config."""

    local = load_local_config(engagement)
    lhost = str(local.get("lhost") or "") or None
    lport = _int_or_none(local.get("lport"))
    host_notes = _load_host_notes(engagement.notes_dir)
    credentials = _workspace_credentials(engagement.root, credential_user)
    defenses = _detect_defenses(
        load_findings(engagement), _hosts_from_notes(host_notes)
    )
    host_keys = _target_hosts(host, host_notes, credentials)
    contexts: list[PayloadContext] = []
    for host_key in host_keys:
        note_context = host_notes.get(host_key) or _parse_host_note(
            host_note_path(engagement.notes_dir, host_key)
        )
        host_ip = note_context.get("host_ip") or host_key
        host_credentials = [
            credential
            for credential in credentials
            if credential.source_host in {host_key, host_ip}
        ]
        if credential_user and not host_credentials:
            continue
        contexts.append(
            PayloadContext(
                host_ip=host_ip,
                hostname=note_context.get("hostname"),
                os=note_context.get("os"),
                open_ports=sorted(set(note_context.get("open_ports", []))),
                credentials=host_credentials,
                domain=_first_domain(host_credentials),
                lhost=lhost,
                lport=lport,
                defenses=defenses,
            )
        )
    return contexts


def _detect_defenses(
    findings: list[Finding],
    hosts: list[Host] | None = None,
) -> DefenseProfile:
    """Scan finding evidence for AV/EDR indicators."""

    av: set[str] = set()
    edr: set[str] = set()
    for host in hosts or []:
        for product in host.av_products:
            if _categorize_av(product) == "edr":
                edr.add(product)
            else:
                av.add(product)

    combined = " ".join(
        part
        for finding in findings
        for part in [finding.evidence, finding.title, *finding.next_steps]
    ).lower()
    for product, indicators in AV_INDICATORS.items():
        if any(indicator.lower() in combined for indicator in indicators):
            label = PRODUCT_LABELS[product]
            if product in EDR_PRODUCTS:
                edr.add(label)
            else:
                av.add(label)
    return DefenseProfile(
        av_detected=sorted(av),
        edr_detected=sorted(edr),
        logging_detected=_logging_products(combined),
        applocker="applocker" in combined,
        constrained_lang="constrainedlanguage" in combined
        or "constrained language" in combined,
        amsi_present=bool(av or edr),
    )


def _categorize_av(product: str) -> str:
    lowered = product.casefold()
    for key, indicators in AV_INDICATORS.items():
        if key in lowered or any(
            indicator.casefold() in lowered for indicator in indicators
        ):
            return "edr" if key in EDR_PRODUCTS else "av"
    return "av"


def _logging_products(text: str) -> list[str]:
    products = []
    if "splunk" in text:
        products.append("Splunk")
    if "sysmon" in text:
        products.append("Sysmon")
    return products


def _workspace_credentials(
    vault_root: Path,
    credential_user: str | None,
) -> list[WorkspaceCredential]:
    filters = {"user": credential_user} if credential_user else {}
    return [
        WorkspaceCredential.model_validate(item)
        for item in WorkspaceStore(vault_root).get_credentials(filters)
    ]


def _target_hosts(
    host: str | None,
    host_notes: dict[str, dict],
    credentials: list[WorkspaceCredential],
) -> list[str]:
    if host:
        return [host]
    hosts = set(host_notes)
    hosts.update(
        credential.source_host
        for credential in credentials
        if credential.source_host and credential.source_host != "unknown"
    )
    return sorted(hosts)


def _load_host_notes(notes_dir: Path) -> dict[str, dict]:
    host_dir = notes_dir / "hosts"
    if not host_dir.exists():
        return {}
    contexts: dict[str, dict] = {}
    for path in sorted(host_dir.glob("*.md")):
        context = _parse_host_note(path)
        host_ip = context.get("host_ip")
        if host_ip:
            contexts[host_ip] = context
    return contexts


def _hosts_from_notes(host_notes: dict[str, dict]) -> list[Host]:
    return [
        Host(
            ip=context.get("host_ip") or host_ip,
            hostname=context.get("hostname"),
            os=context.get("os"),
            av_products=list(dict.fromkeys(context.get("av_products", []))),
        )
        for host_ip, context in host_notes.items()
    ]


def _parse_host_note(path: Path) -> dict:
    if not path.exists():
        return {
            "host_ip": None,
            "hostname": None,
            "os": None,
            "open_ports": [],
            "av_products": [],
        }
    text = path.read_text(encoding="utf-8")
    return {
        "host_ip": _target_info_value(text, "IP"),
        "hostname": _target_info_value(text, "Hostname"),
        "os": _target_info_value(text, "OS"),
        "open_ports": _open_ports(text),
        "av_products": _security_products(text),
    }


def _target_info_value(markdown: str, field: str) -> str | None:
    prefix = f"| {field} |"
    for line in markdown.splitlines():
        if not line.startswith(prefix):
            continue
        value = line.removeprefix(prefix).strip().strip("|").strip()
        return None if value == "N/A" else value
    return None


def _open_ports(markdown: str) -> list[int]:
    ports: list[int] = []
    in_ports = False
    for line in markdown.splitlines():
        if line == "## Open Ports":
            in_ports = True
            continue
        if in_ports and line.startswith("## "):
            break
        if not in_ports or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 5 or not cells[0].isdigit():
            continue
        if cells[4].casefold() != "open":
            continue
        ports.append(int(cells[0]))
    return ports


def _security_products(markdown: str) -> list[str]:
    products: list[str] = []
    in_products = False
    for line in markdown.splitlines():
        if line == "## Security Products":
            in_products = True
            continue
        if in_products and line.startswith("## "):
            break
        if not in_products or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2 or cells[0] in {"Product", "---"}:
            continue
        if cells[0] and cells[0] not in products:
            products.append(cells[0])
    return products


def _first_domain(credentials: list[WorkspaceCredential]) -> str | None:
    for credential in credentials:
        if credential.domain:
            return credential.domain
    return None


def _int_or_none(value: object) -> int | None:
    try:
        return int(value) if value not in {None, ""} else None
    except (TypeError, ValueError):
        return None

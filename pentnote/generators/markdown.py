"""Markdown rendering through Jinja2 templates."""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from pentnote.core.models import PentNoteModel
from pentnote.mitre.chain_detector import apply_chain_membership
from pentnote.mitre.classifier import (
    MitreClassifier,
    classify_host_ports,
    default_attack_db_path,
)
from pentnote.mitre.defends import defense_tuples_for_matches
from pentnote.mitre.next_steps import (
    CREDENTIAL_MITRE_TAGS,
    CREDENTIAL_SEVERITY,
    finding_next_steps,
    get_credential_next_steps,
    next_steps_for_host,
)
from pentnote.mitre.scorer import host_severity_reason, severity_for_host
from pentnote.models import (
    Credential,
    DomainObject,
    Finding,
    Host,
    ParsedResult,
    Port,
    TargetGroup,
)
from pentnote.models.finding import Severity

SECRET_TYPE_FOLDERS = {
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
}

DOMAIN_TYPE_FOLDERS = {
    "user": "users",
    "group": "groups",
    "computer": "computers",
    "share": "shares",
    "template": "templates",
    "gpo": "gpos",
    "acl": "acls",
}


class ChainStep(PentNoteModel):
    """Attack-chain progress row for templates."""

    label: str
    completed: bool


def template_env() -> Environment:
    """Create a Jinja2 environment for bundled templates."""

    env = Environment(
        loader=PackageLoader("pentnote", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["md_cell"] = _md_cell
    env.filters["yaml_scalar"] = _yaml_scalar
    env.filters["fence_text"] = _fence_text
    env.filters["slugify"] = slugify
    return env


def render_host_markdown(
    host: Host,
    *,
    engagement_name: str,
    tool_name: str,
    tool_history: list[str] | None = None,
    iso_timestamp: str | None = None,
) -> str:
    """Render a host object to Markdown."""

    _enrich_host(host)
    template = template_env().get_template("host.md.j2")
    return template.render(
        host=host,
        tags=_format_tags(_host_frontmatter_tags(host)),
        tools=_format_list(tool_history or [tool_name]),
        mitre_tags=", ".join(match.technique_id for match in host.mitre_matches)
        or "N/A",
        severity_reason=host_severity_reason(host),
        engagement_name=engagement_name,
        tool_name=tool_name,
        iso_timestamp=iso_timestamp or _now_iso(),
    )


def render_finding_markdown(
    finding: Finding,
    *,
    engagement_name: str,
    tool_name: str,
    hostname: str | None = None,
    iso_timestamp: str | None = None,
) -> str:
    """Render a finding object to Markdown."""

    template = template_env().get_template("finding.md.j2")
    return template.render(
        finding=finding,
        tags=_format_tags(_finding_tags(finding)),
        primary_host=finding.affected_hosts[0] if finding.affected_hosts else "",
        hostname=hostname,
        engagement_name=engagement_name,
        iso_timestamp=iso_timestamp or _now_iso(),
        tool_name=tool_name,
        description=_one_line_description(finding),
        target_info=_target_info(finding),
        cvss=_cvss_for_severity(finding.severity),
        chain_steps=_chain_steps(finding),
        defenses=defense_tuples_for_matches(finding.mitre_matches),
    )


def render_credential_markdown(
    credential: Credential,
    *,
    engagement_name: str,
    tool_name: str,
    iso_timestamp: str | None = None,
) -> str:
    """Render a credential object to Markdown."""

    template = template_env().get_template("credential.md.j2")
    secret_type = credential.secret_type.casefold()
    return template.render(
        credential=credential,
        mitre_tags=CREDENTIAL_MITRE_TAGS.get(secret_type, ["T1078"]),
        severity=CREDENTIAL_SEVERITY.get(secret_type, "high"),
        next_steps=get_credential_next_steps(
            credential.username,
            credential.secret,
            secret_type,
            credential.source_host,
            credential.domain or "",
        ),
        engagement_name=engagement_name,
        tool_name=tool_name,
        iso_timestamp=iso_timestamp or _now_iso(),
    )


def render_domain_object_markdown(
    domain_object: DomainObject,
    *,
    engagement_name: str,
    tool_name: str,
    iso_timestamp: str | None = None,
) -> str:
    """Render a domain object to Markdown."""

    template = template_env().get_template("domain_object.md.j2")
    return template.render(
        domain_object=domain_object,
        properties_json=json.dumps(domain_object.properties, indent=2, sort_keys=True),
        engagement_name=engagement_name,
        tool_name=tool_name,
        iso_timestamp=iso_timestamp or _now_iso(),
    )


def write_result_markdown(
    result: ParsedResult,
    output_dir: Path,
    *,
    engagement_name: str = "PentNote",
    target_groups: list[TargetGroup] | None = None,
) -> list[Path]:
    """Write all Markdown notes for a parsed result."""

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    _enrich_findings(result.findings, target_groups)
    _enrich_hosts(result.hosts)
    _attach_related_finding_hashes(result)

    host_dir = output_dir / "hosts"

    for host in result.hosts:
        host_dir.mkdir(parents=True, exist_ok=True)
        path = host_dir / f"{_slugify(host.ip)}.md"
        existing_note = path.read_text(encoding="utf-8") if path.exists() else None
        rendered = render_host_markdown(
            _merge_existing_host_note(host, existing_note, result.tool),
            engagement_name=engagement_name,
            tool_name=result.tool,
            tool_history=_merge_tool_history(existing_note, result.tool),
        )
        if existing_note:
            rendered = _preserve_notes_section(rendered, existing_note)
        path.write_text(rendered, encoding="utf-8")
        written.append(path)

    for credential in result.credentials:
        path = _credential_path(credential, output_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_credential_markdown(
                credential,
                engagement_name=engagement_name,
                tool_name=result.tool,
            ),
            encoding="utf-8",
        )
        written.append(path)

    for domain_object in result.domain_objects:
        path = _domain_path(domain_object, output_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_domain_object_markdown(
                domain_object,
                engagement_name=engagement_name,
                tool_name=result.tool,
            ),
            encoding="utf-8",
        )
        written.append(path)

    hostnames = {host.ip: host.hostname for host in result.hosts if host.hostname}
    written_findings: list[Finding] = []
    tool_dir: Path = output_dir / "findings" / slugify(result.tool)
    for finding in result.findings:
        path = _finding_path(finding, result.tool, output_dir)
        tool_dir = path.parent
        path.parent.mkdir(parents=True, exist_ok=True)
        primary_host = finding.affected_hosts[0] if finding.affected_hosts else ""
        path.write_text(
            render_finding_markdown(
                finding,
                engagement_name=engagement_name,
                tool_name=result.tool,
                hostname=hostnames.get(primary_host),
            ),
            encoding="utf-8",
        )
        written.append(path)
        written_findings.append(finding)

    if written_findings:
        index_path = write_tool_index(
            result.tool,
            _first_finding_host(written_findings),
            written_findings,
            tool_dir,
            hosts=result.hosts,
            credentials=result.credentials,
        )
        written.append(index_path)
    elif not result.hosts and not result.credentials and not result.domain_objects:
        tool_dir.mkdir(parents=True, exist_ok=True)
        index_path = write_tool_index(
            result.tool,
            "global",
            [],
            tool_dir,
            hosts=[],
            credentials=[],
        )
        written.append(index_path)

    return written


def _finding_path(
    finding: Finding,
    tool: str,
    notes_dir: Path,
) -> Path:
    """Return the hierarchical note path for a finding."""

    tool_dir = notes_dir / "findings" / slugify(tool)
    slug = slugify(_short_title(finding.title, tool), max_length=40)
    path = tool_dir / f"{slug}.md"
    if path.exists() and _read_frontmatter_hash(path) != finding.hash:
        path = tool_dir / f"{slug}-{finding.hash[:6]}.md"
    return path


def _short_title(title: str, tool: str) -> str:
    """Remove tool and common prefixes from a finding title."""

    cleaned = title.strip()
    prefixes = [
        tool,
        "web virtual host discovered",
        "web path discovered",
        "open",
        "found",
    ]
    for prefix in prefixes:
        value = prefix.casefold()
        if cleaned.casefold().startswith(value):
            cleaned = cleaned[len(prefix) :].strip(": -")
            break
    words = cleaned.replace(".", " ").replace(":", " ").split()
    if len(words) >= 3 and len(words[-1]) <= 6 and len(words[-2]) <= 20:
        words = words[:-2]
    short = "-".join(word.casefold() for word in words[:5])
    return short[:40].strip("-") or "finding"


def _credential_path(
    credential: Credential,
    notes_dir: Path,
) -> Path:
    """Return the hierarchical note path for a credential."""

    folder = SECRET_TYPE_FOLDERS.get(credential.secret_type, "other")
    cred_dir = notes_dir / "credentials" / folder
    slug = slugify(credential.username)
    path = cred_dir / f"{slug}.md"
    if path.exists():
        domain_slug = slugify(credential.domain or "unknown")
        path = cred_dir / f"{domain_slug}-{slug}.md"
    return path


def _domain_path(
    obj: DomainObject,
    notes_dir: Path,
) -> Path:
    """Return the hierarchical note path for a domain object."""

    folder = DOMAIN_TYPE_FOLDERS.get(obj.object_type, "other")
    return notes_dir / "domain" / folder / f"{slugify(obj.name)}.md"


def write_tool_index(
    tool: str,
    host: str,
    findings: list[Finding],
    tool_dir: Path,
    *,
    hosts: list[Host] | None = None,
    credentials: list[Credential] | None = None,
    raw_path: Path | None = None,
    parse_duration_ms: int | None = None,
) -> Path:
    """Write the per-tool findings index."""

    index_path = tool_dir / "_index.md"
    template = template_env().get_template("tool_index.md.j2")
    hosts = hosts or []
    credentials = credentials or []
    rows = [
        {
            "short_slug": _finding_path(finding, tool, tool_dir.parent.parent).stem,
            "title": finding.title,
            "severity": finding.severity.value,
            "mitre": (
                finding.mitre_matches[0].technique_id if finding.mitre_matches else "—"
            ),
        }
        for finding in findings
    ]
    is_empty = not findings and not hosts and not credentials
    index_path.write_text(
        template.render(
            tool=tool,
            host=host,
            date=_now_iso(),
            findings=findings,
            hosts=hosts,
            credentials=credentials,
            is_empty=is_empty,
            raw_path=str(raw_path) if raw_path else None,
            parse_duration_ms=parse_duration_ms,
            rows=rows,
            critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in findings if f.severity == Severity.LOW),
            info_count=sum(1 for f in findings if f.severity == Severity.INFO),
        ),
        encoding="utf-8",
    )
    return index_path


def _read_frontmatter_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, line in enumerate(lines):
        if index > 0 and line == "---":
            break
        if line.startswith("hash:"):
            return line.split(":", 1)[1].strip()
    return None


def _first_finding_host(findings: list[Finding]) -> str:
    for finding in findings:
        if finding.affected_hosts:
            return finding.affected_hosts[0]
    return "global"


def _attach_related_finding_hashes(result: ParsedResult) -> None:
    for credential in result.credentials:
        if credential.related_finding_hash:
            continue
        for finding in result.findings:
            if _credential_matches_finding(credential, finding):
                credential.related_finding_hash = finding.hash
                break


def _credential_matches_finding(credential: Credential, finding: Finding) -> bool:
    if credential.source_host not in finding.affected_hosts:
        return False
    evidence = finding.evidence.casefold()
    title = finding.title.casefold()
    username = credential.username.casefold()
    secret = credential.secret.casefold()
    if username in evidence and (secret in evidence or credential.secret_type in title):
        return True
    return username in title and credential.secret_type in title


def _enrich_findings(
    findings: list[Finding],
    target_groups: list[TargetGroup] | None = None,
) -> None:
    if not findings:
        return
    classifier = MitreClassifier(default_attack_db_path())
    for finding in findings:
        _assign_finding_target_group(finding, target_groups or [])
        if not finding.mitre_matches:
            finding.mitre_matches = classifier.classify(finding.title, finding.evidence)
        finding.next_steps = finding_next_steps(finding)
        if not finding.defenses:
            finding.defenses = defense_tuples_for_matches(finding.mitre_matches)
    apply_chain_membership(findings)


def _assign_finding_target_group(
    finding: Finding,
    target_groups: list[TargetGroup],
) -> None:
    if finding.target_group or not target_groups:
        return
    for host in finding.affected_hosts:
        group = _assign_target_group(host, target_groups)
        if group:
            finding.target_group = group
            return


def _assign_target_group(
    host_ip: str,
    target_groups: list[TargetGroup],
) -> str | None:
    """Return the target group name if a host/IP/domain falls in group scope."""

    value = host_ip.casefold()
    for group in target_groups:
        for scope in group.scope:
            try:
                network = ipaddress.ip_network(scope, strict=False)
                if ipaddress.ip_address(host_ip) in network:
                    return group.name
            except ValueError:
                if scope.casefold() in value:
                    return group.name
    return None


def _enrich_hosts(hosts: list[Host]) -> None:
    for host in hosts:
        _enrich_host(host)


def _enrich_host(host: Host) -> None:
    if not host.mitre_matches:
        host.mitre_matches = classify_host_ports(host)
    host.severity = severity_for_host(host)
    if not host.next_steps:
        host.next_steps = next_steps_for_host(host)
    if not host.defenses:
        host.defenses = defense_tuples_for_matches(host.mitre_matches)


def _merge_existing_host_note(
    host: Host, existing_note: str | None, tool_name: str
) -> Host:
    if not existing_note:
        return host

    hostname, hostname_aliases = _merge_hostname(
        host.hostname, tool_name, existing_note
    )
    merged = Host(
        ip=host.ip,
        hostname=hostname,
        hostname_aliases=hostname_aliases,
        os=host.os or _target_info_value(existing_note, "OS"),
        ports=_merge_ports(_ports_from_note(existing_note), host.ports),
        tags=list(dict.fromkeys(host.tags)),
        av_products=list(
            dict.fromkeys([*_av_products_from_note(existing_note), *host.av_products])
        ),
    )
    return merged


# Tools that resolve a host's actual AD/NetBIOS computer name (e.g. crackmapexec's
# SMB negotiation) outrank DNS/PTR-derived names (e.g. nmap's reverse-DNS lookup),
# which are often just engagement aliases rather than the host's real identity.
_HOSTNAME_AUTHORITATIVE_TOOLS = frozenset({"crackmapexec"})


def _merge_hostname(
    incoming: str | None, tool_name: str, existing_note: str
) -> tuple[str | None, list[str]]:
    """Resolve the primary hostname plus any superseded aliases.

    A superseded hostname is never discarded outright -- it is kept as an
    alias so engagement nicknames and DNS names remain discoverable even
    after a more authoritative tool identifies the host under another name.
    A tool re-running always gets to refresh its own previously-reported
    value (e.g. nmap correcting a stale PTR record); the authoritative-tool
    priority only decides ties between two *different* tools.
    """

    existing_hostname = _target_info_value(existing_note, "Hostname")
    aliases = _hostname_aliases_from_note(existing_note)

    if not incoming:
        return existing_hostname, aliases
    if not existing_hostname or incoming == existing_hostname:
        return incoming, aliases

    same_tool_rerun = tool_name == _last_tool_from_note(existing_note)
    if same_tool_rerun or tool_name in _HOSTNAME_AUTHORITATIVE_TOOLS:
        primary, demoted = incoming, existing_hostname
    else:
        primary, demoted = existing_hostname, incoming

    if demoted not in aliases:
        aliases = [*aliases, demoted]
    return primary, aliases


def _last_tool_from_note(markdown: str) -> str | None:
    for index, line in enumerate(markdown.splitlines()):
        if index > 0 and line == "---":
            break
        if line.startswith("tool:"):
            return line.split(":", 1)[1].strip()
    return None


def _hostname_aliases_from_note(markdown: str) -> list[str]:
    value = _target_info_value(markdown, "Also Known As")
    if not value:
        return []
    return [alias.strip() for alias in value.split(",") if alias.strip()]


def _av_products_from_note(markdown: str) -> list[str]:
    products: list[str] = []
    in_section = False
    for line in markdown.splitlines():
        if line == "## Security Products":
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if not in_section or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2 or not cells[0] or cells[0] in ("Product", "---"):
            continue
        products.append(cells[0])
    return products


def _merge_tool_history(existing_note: str | None, current_tool: str) -> list[str]:
    history = _tools_from_note(existing_note) if existing_note else []
    if current_tool not in history:
        history = [*history, current_tool]
    return history


def _tools_from_note(markdown: str) -> list[str]:
    tool_value: str | None = None
    for index, line in enumerate(markdown.splitlines()):
        if index > 0 and line == "---":
            break
        if line.startswith("tools:"):
            return _parse_bracket_list(line.split(":", 1)[1])
        if line.startswith("tool:"):
            tool_value = line.split(":", 1)[1].strip()
    return [tool_value] if tool_value else []


def _parse_bracket_list(raw: str) -> list[str]:
    value = raw.strip().strip("[]").strip()
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _merge_ports(existing: list[Port], incoming: list[Port]) -> list[Port]:
    ports: dict[tuple[int, str], Port] = {}
    for port in [*existing, *incoming]:
        ports[(port.number, port.protocol.casefold())] = port
    return sorted(ports.values(), key=lambda port: (port.number, port.protocol))


def _ports_from_note(markdown: str) -> list[Port]:
    ports: list[Port] = []
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
        ports.append(
            Port(
                number=int(cells[0]),
                protocol=cells[1],
                service=cells[2],
                version=None if cells[3] == "N/A" else cells[3],
                state=cells[4],
            )
        )
    return ports


def _target_info_value(markdown: str, field: str) -> str | None:
    prefix = f"| {field} |"
    for line in markdown.splitlines():
        if line.startswith(prefix):
            value = line.removeprefix(prefix).strip().strip("|").strip()
            return None if value == "N/A" else value
    return None


def _preserve_notes_section(rendered: str, existing_note: str) -> str:
    notes = _section_body(existing_note, "## Notes")
    if not notes or notes.strip() == "<!-- analyst notes here -->":
        return rendered
    return rendered.replace(
        "## Notes\n<!-- analyst notes here -->",
        f"## Notes\n{notes.rstrip()}",
    )


def _section_body(markdown: str, heading: str) -> str:
    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        if line == heading:
            body: list[str] = []
            for body_line in lines[index + 1 :]:
                if body_line.startswith("## "):
                    break
                body.append(body_line)
            return "\n".join(body).strip()
    return ""


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _slugify(value: str, max_length: int = 80) -> str:
    slug = []
    previous_dash = False
    for char in value.casefold().strip():
        if char.isalnum():
            slug.append(char)
            previous_dash = False
        elif not previous_dash:
            slug.append("-")
            previous_dash = True
    return ("".join(slug).strip("-") or "note")[:max_length].strip("-")


def slugify(value: str, max_length: int = 80) -> str:
    """Public slug helper for generators and migration."""

    return _slugify(value, max_length=max_length)


def _format_tags(tags: list[str]) -> str:
    cleaned = []
    for tag in tags:
        value = tag.strip().replace(" ", "-")
        if value and value not in cleaned:
            cleaned.append(value)
    return "[" + ", ".join(cleaned) + "]"


def _format_list(values: list[str]) -> str:
    cleaned = list(dict.fromkeys(value.strip() for value in values if value.strip()))
    return "[" + ", ".join(cleaned) + "]"


def _md_cell(value: object) -> str:
    return (
        str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")
    )


def _yaml_scalar(value: object) -> str:
    text = (
        str(value if value is not None else "").replace("\n", " ").replace('"', '\\"')
    )
    return f'"{text}"' if any(char in text for char in ":#[]{}|>") else text


def _fence_text(value: object) -> str:
    return str(value if value is not None else "").replace("```", "` ` `")


def _host_frontmatter_tags(host: Host) -> list[str]:
    services = [
        port.service.casefold()
        for port in host.ports
        if port.state == "open" and port.service
    ]
    os_tags = [host.os.casefold()] if host.os else []
    return [
        "host",
        *[match.technique_id for match in host.mitre_matches],
        *services,
        *[tag.casefold() for tag in host.tags],
        *os_tags,
    ]


def _finding_tags(finding: Finding) -> list[str]:
    return [
        *[match.technique_id for match in finding.mitre_matches],
        finding.severity.value,
    ]


def _one_line_description(finding: Finding) -> str:
    first_line = finding.evidence.strip().splitlines()[0] if finding.evidence else ""
    return first_line or "Parser generated this normalized security finding."


def _target_info(finding: Finding) -> list[tuple[str, str]]:
    return [
        ("Affected Hosts", ", ".join(finding.affected_hosts) or "N/A"),
        ("Evidence", _one_line_description(finding)),
    ]


def _cvss_for_severity(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFO: 0.0,
    }[severity]


def _chain_steps(finding: Finding) -> list[ChainStep]:
    if finding.chain_member is None:
        return []
    return [ChainStep(finding.chain_member, True)]

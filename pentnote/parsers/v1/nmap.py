"""Nmap XML parser."""

from __future__ import annotations

import re
from io import BytesIO

from lxml import etree

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, Host, MitreMatch, ParsedResult, Port, Severity
from pentnote.parsers.base import AbstractParser, ParserError

HIGH_SIGNAL_SCRIPTS: dict[str, tuple[str, Severity, list[str]]] = {
    "smb-vuln-ms17-010": ("MS17-010 EternalBlue", Severity.CRITICAL, ["T1210"]),
    "smb-vuln-cve-2020-0796": ("SMBGhost CVE-2020-0796", Severity.CRITICAL, ["T1210"]),
    "ssl-heartbleed": ("Heartbleed", Severity.CRITICAL, ["T1190"]),
    "vulners": ("Vulnerabilities via Vulners", Severity.HIGH, ["T1190"]),
}


class NmapParser(AbstractParser):
    """Parse Nmap XML or normal text output into host objects."""

    tool_name = "nmap"
    aliases = ("nmap-xml",)
    supported_extensions = (".xml",)

    def can_parse(self, content: str) -> float:
        """Score whether content is Nmap output.

        Args:
            content: Raw tool output.

        Returns:
            Confidence between 0.0 and 1.0.
        """

        clean = self.clean(content).lstrip()
        if not clean:
            return 0.0

        score = 0.0
        sample = clean[:2000]
        if clean.startswith("<?xml"):
            score += 0.2
        if "<nmaprun" in sample:
            score += 0.65
        if 'scanner="nmap"' in sample:
            score += 0.15
        if "Nmap scan report for " in sample:
            score += 0.65
        if re.search(r"(?m)^PORT\s+STATE\s+SERVICE(?:\s+VERSION)?\s*$", sample):
            score += 0.25
        if sample.startswith("Starting Nmap"):
            score += 0.1
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Nmap XML or normal text content.

        Args:
            content: Raw Nmap XML.

        Returns:
            Parsed result containing host objects.

        Raises:
            ParserError: If no XML root can be recovered.
        """

        clean = self.clean(content)
        if self._looks_like_xml(clean):
            return self._parse_xml(clean, content)
        return self._parse_text(clean, content)

    def _looks_like_xml(self, content: str) -> bool:
        clean = content.lstrip()
        return clean.startswith("<?xml") or clean.startswith("<nmaprun")

    def _parse_xml(self, clean: str, raw_text: str) -> ParsedResult:
        try:
            source = BytesIO(clean.encode("utf-8"))
            context = etree.iterparse(
                source,
                events=("end",),
                tag=("nmaprun", "host"),
                recover=True,
                resolve_entities=False,
                no_network=True,
            )
            hosts: list[Host] = []
            findings: list[Finding] = []
            saw_root = False
            for _, node in context:
                if node.tag == "nmaprun":
                    saw_root = True
                    continue
                host = self._host(node)
                if host is not None:
                    hosts.append(host)
                    findings.extend(self._script_findings(node, host.ip))
                node.clear()
        except (OSError, etree.XMLSyntaxError) as exc:
            raise ParserError(f"Invalid Nmap XML: {exc}") from exc

        if not saw_root:
            raise ParserError("Input is not an Nmap XML document.")

        return ParsedResult(
            tool=self.tool_name,
            partial=bool(context.error_log),
            hosts=hosts,
            credentials=[],
            findings=findings,
            domain_objects=[],
            raw_text=raw_text,
        )

    def _parse_text(self, clean: str, raw_text: str) -> ParsedResult:
        hosts: list[Host] = []
        for block in re.split(r"(?m)(?=^Nmap scan report for )", clean):
            block = block.strip()
            if not block.startswith("Nmap scan report for "):
                continue
            host = self._text_host(block)
            if host is not None:
                hosts.append(host)

        if not hosts:
            raise ParserError(
                "Input is not recognized as Nmap output. For XML scans, use: "
                "nmap ... -oX - | pentnote parse --tool nmap"
            )

        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=hosts,
            credentials=[],
            findings=[],
            domain_objects=[],
            raw_text=raw_text,
        )

    def _host(self, node: etree._Element) -> Host | None:
        ip = self._address(node)
        if ip is None:
            return None

        return Host(
            ip=ip,
            hostname=self._hostname(node),
            os=self._extract_os(node),
            ports=self._ports(node),
            tags=self._tags(node),
        )

    def _address(self, node: etree._Element) -> str | None:
        address = node.find("./address[@addrtype='ipv4']")
        if address is None:
            address = node.find("./address")
        return address.get("addr") if address is not None else None

    def _hostname(self, node: etree._Element) -> str | None:
        hostname = node.find("./hostnames/hostname")
        return hostname.get("name") if hostname is not None else None

    def _extract_os(self, host_elem: etree._Element) -> str | None:
        """Extract OS using osmatch, service CPE, then script Service Info."""

        os_match = host_elem.find(".//osmatch")
        if os_match is not None:
            name = os_match.get("name", "").strip()
            if name:
                return name

        for service in host_elem.findall(".//service"):
            os_from_cpe = _parse_os_from_cpe(service.get("cpe", ""))
            if os_from_cpe:
                return os_from_cpe
            for cpe_node in service.findall("./cpe"):
                os_from_cpe = _parse_os_from_cpe(cpe_node.text or "")
                if os_from_cpe:
                    return os_from_cpe

        for script in host_elem.findall(".//script"):
            os_from_script = _parse_os_from_service_info(script.get("output", ""))
            if os_from_script:
                return os_from_script

        return None

    def _ports(self, node: etree._Element) -> list[Port]:
        ports: list[Port] = []
        for port_node in node.findall("./ports/port"):
            state_node = port_node.find("./state")
            service_node = port_node.find("./service")
            service = (
                service_node.get("name") if service_node is not None else "unknown"
            )
            version = self._service_version(service_node)

            ports.append(
                Port(
                    number=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", "tcp"),
                    service=service,
                    version=version,
                    state=(
                        state_node.get("state", "unknown")
                        if state_node is not None
                        else "unknown"
                    ),
                )
            )
        return ports

    def _service_version(self, service_node: etree._Element | None) -> str | None:
        if service_node is None:
            return None
        parts = [
            service_node.get("product"),
            service_node.get("version"),
            service_node.get("extrainfo"),
        ]
        version = " ".join(part for part in parts if part)
        return version or None

    def _tags(self, node: etree._Element) -> list[str]:
        return self._tags_from_ports_and_scripts(self._ports(node), node)

    def _text_host(self, block: str) -> Host | None:
        lines = block.splitlines()
        ip, hostname = self._text_address(lines[0])
        if ip is None:
            return None

        ports = self._text_ports(lines)
        os_name = self._text_os(lines)
        return Host(
            ip=ip,
            hostname=hostname,
            os=os_name,
            ports=ports,
            tags=self._tags_from_ports(ports),
        )

    def _text_address(self, report_line: str) -> tuple[str | None, str | None]:
        target = report_line.removeprefix("Nmap scan report for ").strip()
        match = re.fullmatch(r"(?P<hostname>.+?) \((?P<ip>[^)]+)\)", target)
        if match:
            return match.group("ip"), match.group("hostname")
        return target or None, None

    def _text_ports(self, lines: list[str]) -> list[Port]:
        ports: list[Port] = []
        in_ports = False
        port_pattern = re.compile(
            r"^(?P<number>\d+)\/(?P<protocol>\S+)\s+"
            r"(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
        )
        for line in lines:
            if re.match(r"^PORT\s+STATE\s+SERVICE(?:\s+VERSION)?\s*$", line):
                in_ports = True
                continue
            if not in_ports:
                continue
            if not line.strip() or line.startswith(("Service Info:", "Nmap done:")):
                break
            if line.startswith("|") or line.startswith("_"):
                continue

            match = port_pattern.match(line)
            if match is None:
                continue
            ports.append(
                Port(
                    number=int(match.group("number")),
                    protocol=match.group("protocol"),
                    service=match.group("service"),
                    version=match.group("version") or None,
                    state=match.group("state"),
                )
            )
        return ports

    def _text_os(self, lines: list[str]) -> str | None:
        for line in lines:
            if line.startswith("Service Info:"):
                match = re.search(r"\bOSs?: ([^;]+)", line)
                if match:
                    return match.group(1).strip()
        return None

    def _tags_from_ports_and_scripts(
        self, ports: list[Port], node: etree._Element
    ) -> list[str]:
        tags = set(self._tags_from_ports(ports))
        for script_node in node.findall("./hostscript/script"):
            output = (script_node.get("output") or "").casefold()
            if "domain controller" in output:
                tags.add("active-directory")
        return sorted(tags)

    def _tags_from_ports(self, ports: list[Port]) -> list[str]:
        tags: set[str] = set()
        for port in ports:
            if port.state != "open":
                continue
            if port.number in {139, 445}:
                tags.add("smb")
            if port.number == 3389:
                tags.add("rdp")
            if port.number in {53, 88, 389, 636}:
                tags.add("active-directory")

        return sorted(tags)

    def _script_findings(self, node: etree._Element, host: str) -> list[Finding]:
        findings: list[Finding] = []
        for script in node.findall(".//script"):
            script_id = script.get("id", "")
            spec = HIGH_SIGNAL_SCRIPTS.get(script_id)
            if spec is None:
                continue
            title, severity, technique_ids = spec
            output = script.get("output", "").strip()
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    mitre_matches=[
                        _script_match(technique_id) for technique_id in technique_ids
                    ],
                    affected_hosts=[host],
                    evidence=output or etree.tostring(script, encoding="unicode"),
                    next_steps=[],
                    defenses=[],
                    chain_member=None,
                    hash=finding_hash(self.tool_name, host, title),
                )
            )
        return findings


def _parse_os_from_cpe(cpe: str) -> str | None:
    """Parse OS name from an OS CPE string."""

    if not cpe or not cpe.startswith("cpe:/o:"):
        return None

    parts = cpe.split(":")
    if len(parts) < 3:
        return None

    vendor = parts[2].lower()
    cpe_os_map = {
        "linux": "Linux",
        "microsoft": "Windows",
        "apple": "macOS",
        "freebsd": "FreeBSD",
        "openbsd": "OpenBSD",
        "netbsd": "NetBSD",
        "sun": "Solaris",
        "oracle": "Solaris",
        "cisco": "Cisco IOS",
        "juniper": "Juniper",
        "android": "Android",
    }
    return cpe_os_map.get(vendor)


def _script_match(technique_id: str) -> MitreMatch:
    names = {
        "T1190": ("Exploit Public-Facing Application", "Initial Access"),
        "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    }
    name, tactic = names.get(technique_id, (technique_id, "Unknown"))
    return MitreMatch(technique_id, name, tactic, 1.0, "rule")


def _parse_os_from_service_info(script_output: str) -> str | None:
    """Parse OS from Nmap script output containing Service Info."""

    if "Service Info" not in script_output or "OS:" not in script_output:
        return None

    match = re.search(r"OS:\s*([^;]+)", script_output)
    if match:
        return match.group(1).strip()
    return None

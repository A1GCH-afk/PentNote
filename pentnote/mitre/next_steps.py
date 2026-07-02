"""Suggested next actions for MITRE ATT&CK techniques."""

from __future__ import annotations

import re

from pentnote.models import Finding, Host, MitreMatch, Port, WorkspaceCredential

NEXT_STEPS: dict[str, list[str]] = {
    "T1046": ["Validate exposed services and prioritize reachable management ports."],
    "T1557.001": ["Confirm SMB signing requirements and test relay only in scope."],
    "T1558.003": ["Request service ticket evidence and assess password strength."],
    "T1558.004": ["Verify preauthentication settings for affected accounts."],
    "T1550.002": ["Validate pass-the-hash exposure and rotate affected credentials."],
    "T1110.003": ["Review lockout policy and authentication telemetry."],
    "T1021.001": ["Confirm RDP access control and network segmentation."],
    "T1021.002": ["Review SMB admin share exposure and local admin reuse."],
    "T1003.001": ["Confirm LSASS protection and credential guard posture."],
    "T1003.002": ["Rotate local account hashes and inspect dump source host."],
    "T1003.006": ["Audit replication privileges and domain controller activity."],
    "T1190": ["Validate exploitability and identify exposed application owners."],
}

PORT_NEXT_STEPS: dict[int, list[str]] = {
    22: [
        "Test for weak/default credentials → T1110.001",
        "Check {version} for known CVEs",
    ],
    80: [
        "Run gobuster/feroxbuster for directory enumeration → T1083",
        "Check {version} for CVEs → T1190",
        "Run Nikto web scan",
    ],
    443: [
        "Run gobuster/feroxbuster for directory enumeration → T1083",
        "Check SSL/TLS config (sslscan/testssl)",
        "Check {version} for CVEs → T1190",
    ],
    445: [
        "Check SMB signing (crackmapexec) → T1557.001",
        "Enumerate shares anonymously → T1135",
        "Check for EternalBlue MS17-010 → T1210",
    ],
    3389: [
        "Test RDP for weak credentials → T1110.001",
        "Check for BlueKeep CVE-2019-0708",
        "Try NLA bypass techniques",
    ],
    88: [
        "Enumerate Kerberoastable accounts → T1558.003",
        "Test AS-REP Roasting → T1558.004",
        "Run BloodHound collection",
    ],
    389: [
        "Enumerate LDAP anonymously → T1069.002",
        "Run LDAPDomainDump",
        "Check for LDAP signing requirements",
    ],
    21: [
        "Test anonymous FTP login → T1083",
        "Check for writable directories",
        "Look for sensitive files",
    ],
    25: [
        "Test SMTP open relay",
        "Enumerate valid users via VRFY/EXPN → T1589.002",
    ],
    2049: [
        "Check NFS exports → T1083",
        "Mount NFS shares and check permissions",
    ],
}

CREDENTIAL_MITRE_TAGS: dict[str, list[str]] = {
    "plaintext": ["T1078", "T1110.001"],
    "ntlm": ["T1078", "T1550.002"],
    "kerberos": ["T1078", "T1558.003"],
    "net-ntlmv2": ["T1557.001", "T1040"],
    "net-ntlmv1": ["T1557.001", "T1040"],
}

CREDENTIAL_SEVERITY: dict[str, str] = {
    "plaintext": "critical",
    "ntlm": "high",
    "kerberos": "high",
    "net-ntlmv2": "high",
    "net-ntlmv1": "high",
}

NEXT_STEPS_PLAINTEXT = [
    "Spray credential across subnet:\n      "
    "cme smb {subnet}/24 -u {username} -p {secret}",
    "Check accessible shares:\n      "
    "cme smb {host} -u {username} -p {secret} --shares",
    "Check group memberships:\n      "
    "cme smb {host} -u {username} -p {secret} --groups",
    "Try WinRM if port 5985 is open:\n      "
    "evil-winrm -i {host} -u {username} -p {secret}",
    "Try RDP if port 3389 is open:\n      "
    "xfreerdp /u:{username} /p:{secret} /v:{host}",
    "Check if Domain Admin:\n      "
    "cme smb {host} -u {username} -p {secret} --groups | grep -i 'domain admin'",
]

NEXT_STEPS_NTLM = [
    "Pass the Hash across subnet:\n      "
    "cme smb {subnet}/24 -u {username} -H {secret}",
    "Pass the Hash - check shares:\n      "
    "cme smb {host} -u {username} -H {secret} --shares",
    "Pass the Hash - WinRM:\n      " "evil-winrm -i {host} -u {username} -H {secret}",
    "Crack offline with hashcat:\n      "
    "hashcat -m 1000 {secret} /usr/share/wordlists/rockyou.txt",
    "Check if Domain Admin:\n      "
    "cme smb {host} -u {username} -H {secret} --groups | grep -i 'domain admin'",
]

NEXT_STEPS_KERBEROS = [
    "Crack ticket offline:\n      "
    "hashcat -m 13100 ticket.hash /usr/share/wordlists/rockyou.txt",
    "Pass the Ticket:\n      "
    "python3 getTGT.py {domain}/{username} -hashes :{secret}",
    "Request service tickets:\n      "
    "python3 getST.py -spn cifs/{host} {domain}/{username}",
]

NEXT_STEPS_NET_NTLMV2 = [
    "Crack captured Net-NTLMv2 offline:\n      "
    "hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt",
    "Attempt NTLM relay if SMB signing is disabled:\n      "
    "ntlmrelayx.py -tf relay-targets.txt -smb2support",
]

NEXT_STEPS_NET_NTLMV1 = [
    "Crack captured Net-NTLMv1 offline:\n      "
    "hashcat -m 5500 hash.txt /usr/share/wordlists/rockyou.txt",
    "Confirm capture source and rotate affected credential material.",
]


def suggest_next_steps(matches: list[MitreMatch]) -> list[str]:
    """Return de-duplicated next steps for matched techniques."""

    steps: list[str] = []
    for match in matches:
        for step in NEXT_STEPS.get(match.technique_id, []):
            if step not in steps:
                steps.append(step)
    return steps


def get_next_steps_for_ttp(technique_id: str) -> list[str]:
    """Return generic next steps for one technique."""

    return list(NEXT_STEPS.get(technique_id, []))


def get_contextual_next_steps(
    discovered_ttps: list[str],
    findings: list[Finding],
    credentials: list[WorkspaceCredential],
    hosts: list[str],
    show_secret: bool = False,
) -> list[str]:
    """Generate next steps using real engagement data when available."""

    del findings
    primary_host = hosts[0] if hosts else "{HOST}"
    best_cred = _pick_best_credential(credentials)
    username = best_cred.username if best_cred else "{USER}"
    secret = (
        _credential_secret_for_cli(best_cred, show_secret) if best_cred else "{PASS}"
    )
    hash_secret = _credential_hash_for_cli(best_cred) if best_cred else "{HASH}"
    is_hash = best_cred.secret_type in ("ntlm", "net-ntlmv2") if best_cred else False

    def pass_the_hash_steps() -> list[str]:
        if is_hash:
            return [
                f"cme smb {primary_host} -u {username} -H {hash_secret} --shares",
                f"evil-winrm -i {primary_host} -u {username} -H {hash_secret}",
                f"cme smb {_get_subnet(primary_host)}/24 -u {username} -H {hash_secret}",
            ]
        return [
            f"cme smb {primary_host} -u {username} -p '{secret}' --shares",
            f"evil-winrm -i {primary_host} -u {username} -p '{secret}'",
        ]

    ttp_contextual_steps = {
        "T1550.002": pass_the_hash_steps,
        "T1558.003": lambda: [
            "hashcat -m 13100 kerberos.hash /usr/share/wordlists/rockyou.txt",
            "# Or crack with john:",
            "john --wordlist=/usr/share/wordlists/rockyou.txt kerberos.hash",
            f"python3 getTGT.py DOMAIN/{username}:'{secret}' -dc-ip {primary_host}",
        ],
        "T1558.004": lambda: [
            "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt",
        ],
        "T1557.001": lambda: [
            "# Verify SMB signing first:",
            f"cme smb {primary_host} --gen-relay-list targets.txt",
            "responder -I eth0 -dwv",
            "ntlmrelayx.py -tf targets.txt -smb2support",
        ],
        "T1003.001": lambda: [
            "# LSASS already dumped — check credential notes",
            f"pentnote creds list --host {primary_host}",
            "pentnote creds export --format hashcat --type ntlm --output ntlm.txt",
        ],
    }

    steps: list[str] = []
    for technique_id in discovered_ttps:
        contextual = ttp_contextual_steps.get(technique_id)
        if contextual:
            steps.extend(contextual())
        else:
            steps.extend(get_next_steps_for_ttp(technique_id))
    return _dedupe_steps(steps)


def _pick_best_credential(
    creds: list[WorkspaceCredential],
) -> WorkspaceCredential | None:
    """Pick the most useful credential for command generation."""

    if not creds:
        return None
    for secret_type in ("plaintext", "ntlm", "net-ntlmv2"):
        for credential in creds:
            if credential.secret_type == secret_type:
                return credential
    return creds[0]


def _credential_secret_for_cli(
    credential: WorkspaceCredential | None,
    show_secret: bool,
) -> str:
    if credential is None:
        return "{PASS}"
    if credential.secret_type == "plaintext" and not show_secret:
        return "{PASS}"
    return credential.secret


def _credential_hash_for_cli(credential: WorkspaceCredential | None) -> str:
    if credential is None:
        return "{HASH}"
    return credential.secret[:32]


def finding_next_steps(finding: Finding) -> list[str]:
    """Return actionable finding-specific next steps, preserving parser context."""

    host = finding.affected_hosts[0] if finding.affected_hosts else "TARGET"
    title = finding.title.casefold()
    evidence = finding.evidence
    steps: list[str] = []

    if "valid credential" in title or "administrative access" in title:
        credential = _credential_from_evidence(evidence)
        if credential:
            username, secret = credential
            subnet = _subnet_for_host(host)
            steps.extend(
                [
                    f"Validate SMB access:\n      cme smb {host} -u {username} -p {secret}",
                    f"Check accessible shares:\n      cme smb {host} -u {username} -p {secret} --shares",
                    f"Spray across subnet:\n      cme smb {subnet}/24 -u {username} -p {secret}",
                    f"Try WinRM if open:\n      evil-winrm -i {host} -u {username} -p {secret}",
                ]
            )
    if "smb signing disabled" in title:
        steps.extend(
            [
                f"Confirm SMB signing:\n      cme smb {host} --gen-relay-list relay-targets.txt",
                "Test relay feasibility in scope:\n      ntlmrelayx.py -tf relay-targets.txt -smb2support",
            ]
        )
    if any(match.technique_id == "T1021.002" for match in finding.mitre_matches):
        steps.append(f"Enumerate SMB shares:\n      cme smb {host} --shares")
    if any(match.technique_id == "T1021.001" for match in finding.mitre_matches):
        steps.append(
            f"Check RDP access controls:\n      nmap -p3389 --script rdp-enum-encryption {host}"
        )
    if any(match.technique_id == "T1190" for match in finding.mitre_matches):
        steps.append(
            f"Validate web exposure:\n      nuclei -u {host} -severity critical,high,medium"
        )

    steps.extend(suggest_next_steps(finding.mitre_matches))
    steps.extend(finding.next_steps)
    return _dedupe_steps(steps)


def next_steps_for_host(host: Host) -> list[str]:
    """Return port-specific next steps for open host services."""

    steps: list[str] = []
    for port in host.ports:
        if port.state != "open":
            continue
        for step in PORT_NEXT_STEPS.get(port.number, []):
            formatted = _format_port_step(port, step)
            if formatted not in steps:
                steps.append(formatted)
    return steps


def _credential_from_evidence(evidence: str) -> tuple[str, str] | None:
    match = re.search(r"\[\+\]\s+(?P<identity>\S+:\S+)", evidence)
    if not match:
        return None
    identity = match.group("identity")
    principal, secret = identity.split(":", 1)
    username = principal.rsplit("\\", 1)[-1]
    return username, secret


def _dedupe_steps(steps: list[str]) -> list[str]:
    deduped: list[str] = []
    for step in steps:
        if step and step not in deduped:
            deduped.append(step)
    return deduped


def get_credential_next_steps(
    username: str,
    secret: str,
    secret_type: str,
    host: str,
    domain: str,
) -> list[str]:
    """Return credential-specific next steps with command templates rendered."""

    steps_by_type = {
        "plaintext": NEXT_STEPS_PLAINTEXT,
        "ntlm": NEXT_STEPS_NTLM,
        "kerberos": NEXT_STEPS_KERBEROS,
        "net-ntlmv2": NEXT_STEPS_NET_NTLMV2,
        "net-ntlmv1": NEXT_STEPS_NET_NTLMV1,
    }
    if secret_type not in steps_by_type:
        preview = f"{secret[:20]}..." if len(secret) > 20 else secret
        return [
            f"Identify hash type: hashid {preview}",
            "Try hashcat auto-detect: hashcat -a 0 hash.txt rockyou.txt",
            "Try john: john --format=auto hash.txt",
        ]
    steps = steps_by_type[secret_type]
    subnet = _subnet_for_host(host)

    return [
        step.format(
            username=username,
            secret=secret,
            host=host,
            domain=domain,
            subnet=subnet,
        )
        for step in steps
    ]


def _format_port_step(port: Port, step: str) -> str:
    service = port.service.upper() if port.service else f"Port {port.number}"
    label = _service_label(port)
    version = port.version or port.service or f"port {port.number}"
    return f"{label} ({port.number}): {step.format(service=service, version=version)}"


def _subnet_for_host(host: str) -> str:
    parts = host.split(".")
    if len(parts) != 4:
        return host
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return host
    if any(octet < 0 or octet > 255 for octet in octets):
        return host
    return ".".join([*parts[:3], "0"])


def _get_subnet(ip: str) -> str:
    """Convert 192.168.56.11 to 192.168.56.0 when possible."""

    return _subnet_for_host(ip)


def _service_label(port: Port) -> str:
    if port.number == 22:
        return "SSH"
    if port.number in {80, 443, 8080, 8443}:
        return "HTTP"
    if port.number == 445:
        return "SMB"
    if port.number == 3389:
        return "RDP"
    if port.number in {88, 389, 636, 3268}:
        return port.service.upper()
    return port.service.upper() if port.service else "Service"

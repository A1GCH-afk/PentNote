"""D3FEND countermeasure mapping."""

from __future__ import annotations

from pentnote.models import DefenseRow, MitreMatch

D3FEND: dict[str, list[str]] = {
    "T1046": ["D3-NTA: Network Traffic Analysis"],
    "T1557.001": ["D3-SFA: Sender Filtering", "D3-ANAA: Authentication Analysis"],
    "T1558.003": ["D3-CFA: Credential Filtering", "D3-LFP: Local File Permissions"],
    "T1558.004": ["D3-AH: Account Hardening"],
    "T1550.002": ["D3-CH: Credential Hardening", "D3-LAM: Local Account Monitoring"],
    "T1110.003": ["D3-AH: Account Hardening", "D3-BA: Behavior Analytics"],
    "T1021.001": ["D3-NI: Network Isolation"],
    "T1021.002": ["D3-SI: Share Isolation"],
    "T1003.001": ["D3-PH: Process Hardening"],
    "T1003.002": ["D3-CH: Credential Hardening"],
    "T1003.006": ["D3-DA: Domain Account Monitoring"],
    "T1190": ["D3-WAF: Web Application Firewall"],
}

DEFENDS_MAP: dict[str, tuple[str, str]] = {
    "T1046": ("D3-NTA", "Network Traffic Analysis"),
    "T1021.004": ("D3-NI", "Network Isolation"),
    "T1021.002": ("D3-NI", "Network Isolation"),
    "T1021.001": ("D3-RDP", "Remote Desktop Protocol Monitoring"),
    "T1190": ("D3-WSAA", "Web Server Access Activity Analysis"),
    "T1110.001": ("D3-MFA", "Multi-Factor Authentication"),
    "T1557.001": ("D3-PH", "Protocol Header Verification"),
    "T1558.003": ("D3-KTA", "Kerberos Traffic Analysis"),
    "T1558.004": ("D3-KTA", "Kerberos Traffic Analysis"),
    "T1003.001": ("D3-PA", "Process Spawn Analysis"),
    "T1003.002": ("D3-PA", "Process Spawn Analysis"),
    "T1003.006": ("D3-DA", "Domain Account Monitoring"),
    "T1135": ("D3-SRA", "Share Permissions Analysis"),
    "T1083": ("D3-FA", "File Access Pattern Analysis"),
    "T1210": ("D3-PM", "Patch Management"),
    "T1114.002": ("D3-ECM", "Email Content Monitoring"),
    "T1071.004": ("D3-DNSM", "DNS Monitoring"),
    "T1021.003": ("D3-DCOMM", "DCOM Monitoring"),
    "T1069.002": ("D3-DA", "Domain Account Monitoring"),
    "T1021.006": ("D3-NI", "Network Isolation"),
}


def defenses_for_matches(matches: list[MitreMatch]) -> list[str]:
    """Return de-duplicated D3FEND countermeasures for matches."""

    defenses: list[str] = []
    for match in matches:
        for defense in D3FEND.get(match.technique_id, []):
            if defense not in defenses:
                defenses.append(defense)
    return defenses


def defense_tuples_for_matches(matches: list[MitreMatch]) -> list[DefenseRow]:
    """Return D3FEND rows as structured technique, ID, description entries."""

    defenses: list[DefenseRow] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        defense = DEFENDS_MAP.get(match.technique_id)
        if defense is None:
            continue
        defense_id, description = defense
        key = (match.technique_id, defense_id)
        if key in seen:
            continue
        seen.add(key)
        defenses.append(DefenseRow(match.technique_id, defense_id, description))
    return defenses

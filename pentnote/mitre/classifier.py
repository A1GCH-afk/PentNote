"""MITRE ATT&CK classifier."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from pentnote.core.models import PentNoteModel
from pentnote.mitre.scorer import merge_matches
from pentnote.models import Host, MitreMatch

PORT_MITRE_RULES: dict[int, list[tuple[str, str, str, float]]] = {
    22: [("T1021.004", "SSH", "Lateral Movement", 0.95)],
    23: [("T1021.004", "Telnet", "Lateral Movement", 0.90)],
    25: [("T1114.002", "Email Collection", "Collection", 0.70)],
    53: [("T1071.004", "DNS", "C2", 0.60)],
    80: [("T1190", "Exploit Public-Facing Application", "Initial Access", 0.80)],
    88: [
        ("T1558.003", "Kerberoasting", "Credential Access", 1.00),
        ("T1558.004", "AS-REP Roasting", "Credential Access", 1.00),
    ],
    110: [("T1114.002", "Email Collection", "Collection", 0.70)],
    135: [("T1021.003", "DCOM", "Lateral Movement", 0.85)],
    139: [("T1021.002", "SMB", "Lateral Movement", 0.90)],
    143: [("T1114.002", "Email Collection", "Collection", 0.70)],
    389: [("T1069.002", "LDAP Enumeration", "Discovery", 0.90)],
    443: [("T1190", "Exploit Public-Facing Application", "Initial Access", 0.80)],
    445: [
        ("T1021.002", "SMB/Admin Shares", "Lateral Movement", 0.90),
        ("T1557.001", "LLMNR/NBT-NS Poisoning", "Credential Access", 0.85),
    ],
    636: [("T1069.002", "LDAP Enumeration", "Discovery", 0.90)],
    1433: [("T1190", "MSSQL Exploit", "Initial Access", 0.85)],
    2049: [("T1083", "NFS File Discovery", "Discovery", 0.90)],
    3268: [("T1069.002", "Global Catalog LDAP", "Discovery", 0.90)],
    3306: [("T1190", "MySQL Exploit", "Initial Access", 0.85)],
    3389: [("T1021.001", "RDP", "Lateral Movement", 0.95)],
    5985: [("T1021.006", "WinRM", "Lateral Movement", 0.95)],
    5986: [("T1021.006", "WinRM HTTPS", "Lateral Movement", 0.95)],
    8080: [("T1190", "Exploit Public-Facing Application", "Initial Access", 0.80)],
    8443: [("T1190", "Exploit Public-Facing Application", "Initial Access", 0.80)],
}

ALWAYS_ADD: list[tuple[str, str, str, float]] = [
    ("T1046", "Network Service Discovery", "Discovery", 1.00)
]

CONFIDENCE_BANDS = {
    "rule": 1.0,
    "port": 0.85,
    "keyword": 0.40,
    "universal": 0.20,
}


class AttackTechnique(PentNoteModel):
    """Indexed ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str
    keywords: frozenset[str]


class AttackDatabase(PentNoteModel):
    """Cached ATT&CK database and keyword index."""

    techniques: dict[str, AttackTechnique]
    keyword_index: dict[str, frozenset[str]]


class MitreClassifier:
    """Rule and keyword based MITRE ATT&CK classifier."""

    def __init__(self, db_path: Path | None = None):
        self._db = self._load_and_index(db_path)
        self._rules = _load_rules()
        self._validate_rules()

    @staticmethod
    @lru_cache(maxsize=8)
    def _load_and_index(db_path: Path | None = None) -> AttackDatabase:
        data = _load_attack_db()
        techniques = _parse_techniques(data)
        keyword_index = {
            technique_id: technique.keywords
            for technique_id, technique in techniques.items()
        }
        return AttackDatabase(techniques=techniques, keyword_index=keyword_index)

    def technique(self, technique_id: str) -> AttackTechnique:
        """Return a technique by ID, falling back to an unknown shell."""

        return self._db.techniques.get(
            technique_id,
            AttackTechnique(
                technique_id=technique_id,
                technique_name=technique_id,
                tactic="Unknown",
                description="",
                keywords=frozenset(),
            ),
        )

    def keyword_match(self, text: str) -> list[MitreMatch]:
        """Match text against ATT&CK technique keyword indexes.

        Args:
            text: Finding title and evidence text.

        Returns:
            Keyword-derived technique matches.
        """

        tokens = _tokenize(text)
        matches: list[MitreMatch] = []
        for technique_id, keywords in self._db.keyword_index.items():
            if not keywords:
                continue
            overlap = tokens & set(keywords)
            if not overlap:
                continue
            technique = self.technique(technique_id)
            matches.append(
                MitreMatch(
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    tactic=technique.tactic,
                    confidence=CONFIDENCE_BANDS["keyword"],
                    source="keyword",
                )
            )
        return matches

    def classify(self, finding_title: str, evidence: str) -> list[MitreMatch]:
        """Classify a finding title and evidence into ATT&CK matches."""

        text = f"{finding_title} {evidence}"
        matches = [*self._rule_match(text), *self.keyword_match(text)]
        return merge_matches(matches)

    def classify_host(self, host: Host) -> list[MitreMatch]:
        """Classify host open ports into ATT&CK techniques."""

        return classify_host_ports(host)

    def _rule_match(self, text: str) -> list[MitreMatch]:
        normalized = _normalize_rule_text(text)
        matches: list[MitreMatch] = []
        for rule_key, technique_ids in self._rules.items():
            if rule_key not in normalized:
                continue
            for technique_id in technique_ids:
                technique = self.technique(technique_id)
                matches.append(
                    MitreMatch(
                        technique_id=technique.technique_id,
                        technique_name=technique.technique_name,
                        tactic=technique.tactic,
                        confidence=CONFIDENCE_BANDS["rule"],
                        source="rule",
                    )
                )
        return matches

    def _validate_rules(self) -> None:
        missing = {
            technique_id
            for technique_ids in self._rules.values()
            for technique_id in technique_ids
            if technique_id not in self._db.techniques
        }
        for technique_id in missing:
            self._db.techniques[technique_id] = AttackTechnique(
                technique_id=technique_id,
                technique_name=technique_id,
                tactic="Unknown",
                description="Rule references a technique absent from the bundled DB.",
                keywords=frozenset(),
            )


def classify_host_ports(host: Host) -> list[MitreMatch]:
    """Return rule-based ATT&CK matches for open services on a host."""

    matches: list[MitreMatch] = []
    if any(port.state == "open" for port in host.ports):
        matches.extend(_port_rules_to_matches(ALWAYS_ADD))

    for port in host.ports:
        if port.state != "open":
            continue
        matches.extend(_port_rules_to_matches(PORT_MITRE_RULES.get(port.number, [])))
    return merge_matches(matches)


def _port_rules_to_matches(
    rules: list[tuple[str, str, str, float]],
) -> list[MitreMatch]:
    return [
        MitreMatch(
            technique_id=technique_id,
            technique_name=name,
            tactic=tactic,
            confidence=confidence,
            source="port",
        )
        for technique_id, name, tactic, confidence in rules
    ]


def default_attack_db_path() -> Path:
    """Return the local enterprise ATT&CK database path."""

    return Path(
        resources.files("pentnote.mitre.data").joinpath("enterprise-attack.json")
    )


@lru_cache(maxsize=1)
def _load_attack_db() -> dict[str, Any]:
    """Load the bundled enterprise ATT&CK database from package data."""

    db_file = resources.files("pentnote.mitre.data").joinpath("enterprise-attack.json")
    with db_file.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, list[str]]:
    rules_path = resources.files("pentnote.mitre.data").joinpath("rules.json")
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    if "ntml_relay" in data and "ntlm_relay" not in data:
        data["ntlm_relay"] = data.pop("ntml_relay")
    return {str(key): [str(value) for value in values] for key, values in data.items()}


def _parse_techniques(data: dict[str, Any]) -> dict[str, AttackTechnique]:
    if "techniques" in data:
        return {
            item["id"]: AttackTechnique(
                technique_id=item["id"],
                technique_name=item["name"],
                tactic=item["tactic"],
                description=item.get("description", ""),
                keywords=frozenset(
                    item.get("keywords") or _tokenize(item.get("description", ""))
                ),
            )
            for item in data["techniques"]
        }
    techniques: dict[str, AttackTechnique] = {}
    for item in data.get("objects", []):
        if item.get("type") != "attack-pattern" or item.get("revoked"):
            continue
        technique_id = _external_id(item)
        if technique_id is None:
            continue
        tactic = _kill_chain_tactic(item)
        description = item.get("description", "")
        techniques[technique_id] = AttackTechnique(
            technique_id=technique_id,
            technique_name=item.get("name", technique_id),
            tactic=tactic,
            description=description,
            keywords=frozenset(_tokenize(f"{item.get('name', '')} {description}")),
        )
    return techniques


def _external_id(item: dict[str, Any]) -> str | None:
    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _kill_chain_tactic(item: dict[str, Any]) -> str:
    phases = item.get("kill_chain_phases") or []
    if not phases:
        return "Unknown"
    phase = phases[0].get("phase_name", "unknown")
    return phase.replace("-", " ").title()


def _tokenize(text: str) -> set[str]:
    token = ""
    tokens: set[str] = set()
    for char in text.casefold():
        if char.isalnum() or char in {"-", "_"}:
            token += char
        elif token:
            tokens.add(token)
            token = ""
    if token:
        tokens.add(token)
    return {value for value in tokens if len(value) > 2}


def _normalize_rule_text(text: str) -> str:
    normalized = []
    previous_underscore = False
    for char in text.casefold():
        if char.isalnum():
            normalized.append(char)
            previous_underscore = False
        elif not previous_underscore:
            normalized.append("_")
            previous_underscore = True
    return "".join(normalized).strip("_")

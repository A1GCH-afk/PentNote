"""Canonical PentNote data contracts backed by Pydantic v2."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SECRET_TYPE_ALIASES: dict[str, str] = {
    "ntlm": "ntlm",
    "nt": "ntlm",
    "lm": "ntlm",
    "plaintext": "plaintext",
    "plain": "plaintext",
    "password": "plaintext",
    "kerberos": "kerberos",
    "kerb": "kerberos",
    "tgs": "kerberos",
    "tgt": "kerberos",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "bcrypt": "bcrypt",
    "net-ntlmv2": "net-ntlmv2",
    "netntlmv2": "net-ntlmv2",
    "net-ntlmv1": "net-ntlmv1",
    "dpapi": "dpapi",
    "aes256": "aes256",
}


def normalize_secret_type_value(value: Any) -> str:
    """Normalize known credential secret-type aliases, preserving unknown types."""

    normalized_input = str(value or "").lower().strip()
    return SECRET_TYPE_ALIASES.get(normalized_input, normalized_input)


class PentNoteModel(BaseModel):
    """Base model with tolerant parsing and legacy positional init support."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    def __init__(self, *args: Any, **data: Any) -> None:
        if args:
            field_names = list(type(self).model_fields)
            if len(args) > len(field_names):
                raise TypeError(
                    f"{type(self).__name__} expected at most {len(field_names)} "
                    f"positional arguments, got {len(args)}"
                )
            for field_name, value in zip(field_names, args, strict=False):
                if field_name in data:
                    raise TypeError(
                        f"{type(self).__name__} got multiple values for "
                        f"argument '{field_name}'"
                    )
                data[field_name] = value
        super().__init__(**data)


class Severity(StrEnum):
    """Normalized finding severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementType(StrEnum):
    """High-level engagement templates used in reports and status output."""

    INTERNAL_AD = "internal-ad"
    EXTERNAL_WEB = "external-web"
    FULL_SCOPE = "full-scope"
    RED_TEAM = "red-team"
    ASSUMED_BREACH = "assumed-breach"


class ExtractionConfidence(StrEnum):
    """Quality gate outcome for Ghost Log LLM extraction."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TargetGroup(PentNoteModel):
    """Named scope subset inside a larger engagement."""

    name: str
    scope: list[str] = Field(default_factory=list)
    description: str = ""


class EngagementConfig(PentNoteModel):
    """Persistent engagement metadata stored in `.pentnote/config.json`."""

    name: str
    client_name: str | None = None
    engagement_type: EngagementType = EngagementType.FULL_SCOPE
    scope: list[str] = Field(default_factory=list)
    start_date: str = ""
    operator: str | None = None
    notes: str | None = None
    target_groups: list[TargetGroup] = Field(default_factory=list)


class Engagement(PentNoteModel):
    """PentNote engagement vault context."""

    root: Path
    name: str
    scope: list[str] = Field(default_factory=list)
    created_at: str
    client_name: str | None = None
    engagement_type: EngagementType = EngagementType.FULL_SCOPE
    start_date: str = ""
    operator: str | None = None
    notes: str | None = None
    target_groups: list[TargetGroup] = Field(default_factory=list)

    @property
    def state_dir(self) -> Path:
        return self.root / ".pentnote"

    @property
    def notes_dir(self) -> Path:
        return self.root / "notes"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def config_path(self) -> Path:
        return self.state_dir / "config.json"

    @property
    def local_config_path(self) -> Path:
        return self.state_dir / "local.json"

    @property
    def findings_path(self) -> Path:
        return self.state_dir / "findings.json"


class MitreMatch(PentNoteModel):
    """MITRE ATT&CK technique match with confidence metadata."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    source: str


class QualityGatedExtraction(PentNoteModel):
    """Validated Ghost Log extraction with quality metadata."""

    raw_extraction: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0
    quality: ExtractionConfidence = ExtractionConfidence.LOW
    validation_notes: list[str] = Field(default_factory=list)


class DefenseRow(PentNoteModel):
    """Structured D3FEND countermeasure mapping."""

    technique_id: str
    defend_id: str
    description: str


class Port(PentNoteModel):
    """Network service observed on a host."""

    number: int
    protocol: str
    service: str
    version: str | None = None
    state: str


class Host(PentNoteModel):
    """Host discovered during parsing."""

    ip: str
    hostname: str | None = None
    hostname_aliases: list[str] = Field(default_factory=list)
    os: str | None = None
    ports: list[Port] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    av_products: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    mitre_matches: list[MitreMatch] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    defenses: list[DefenseRow | str] = Field(default_factory=list)


class Credential(PentNoteModel):
    """Credential material extracted from tool output."""

    username: str
    secret: str
    secret_type: str
    source_host: str
    domain: str | None = None
    cracked: bool = False
    cracked_value: str | None = None
    related_finding_hash: str | None = None

    @field_validator("secret_type", mode="before")
    @classmethod
    def normalize_secret_type(cls, value: Any) -> str:
        """Normalize known credential secret-type aliases."""

        return normalize_secret_type_value(value)


class NetworkPath(PentNoteModel):
    """Relationship edge between two domain objects."""

    source: str
    target: str
    relationship: str


class DomainObject(PentNoteModel):
    """Active Directory or domain object."""

    name: str
    object_type: str
    domain: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)
    paths: list[NetworkPath] = Field(default_factory=list)


class RiskScore(PentNoteModel):
    """Weighted risk score for report prioritization."""

    severity_score: float
    exploitability: float
    lateral_potential: float
    credential_exposure: float
    chain_bonus: float
    total: float


class RemediationItem(PentNoteModel):
    """Prioritized remediation row for client-facing reports."""

    finding_title: str
    severity: Severity
    risk_score: float = 0.0
    d3fend_ids: list[str] = Field(default_factory=list)
    recommendation: str = ""
    effort: str = "Medium"
    priority: int = 0


class Finding(PentNoteModel):
    """Structured security finding emitted by parsers."""

    title: str
    severity: Severity
    mitre_matches: list[MitreMatch] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    evidence: str = ""
    next_steps: list[str] = Field(default_factory=list)
    defenses: list[DefenseRow | str] = Field(default_factory=list)
    chain_member: str | None = None
    hash: str
    risk_score: RiskScore | None = None
    source_command: str | None = None
    target_group: str | None = None


class ParsedResult(PentNoteModel):
    """Normalized parser output."""

    tool: str
    partial: bool = False
    hosts: list[Host] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    domain_objects: list[DomainObject] = Field(default_factory=list)
    raw_text: str = ""


class WorkspaceCredential(PentNoteModel):
    """Credential record persisted in `.pentnote/workspace.json`."""

    id: str = ""
    username: str
    domain: str | None = None
    secret: str = ""
    secret_type: str = ""
    source_host: str = "unknown"
    source_tool: str = "manual"
    cracked: bool = False
    cracked_value: str | None = None
    plaintext: str | None = None
    tags: list[str] = Field(default_factory=list)
    date_added: str = ""
    notes: str = ""
    related_finding_hash: str | None = None

    @field_validator("secret_type", mode="before")
    @classmethod
    def normalize_secret_type(cls, value: Any) -> str:
        """Normalize known credential secret-type aliases."""

        return normalize_secret_type_value(value)


class DefenseProfile(PentNoteModel):
    """Defensive tooling signals inferred from existing findings."""

    av_detected: list[str] = Field(default_factory=list)
    edr_detected: list[str] = Field(default_factory=list)
    logging_detected: list[str] = Field(default_factory=list)
    applocker: bool = False
    constrained_lang: bool = False
    amsi_present: bool = False


class PayloadContext(PentNoteModel):
    """Resolved target context for operator payload guidance."""

    host_ip: str
    hostname: str | None = None
    os: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    credentials: list[WorkspaceCredential] = Field(default_factory=list)
    domain: str | None = None
    lhost: str | None = None
    lport: int | None = None
    defenses: DefenseProfile = Field(default_factory=DefenseProfile)


class WorkspaceNote(PentNoteModel):
    """Manual workspace note record."""

    id: str = ""
    target: str = ""
    target_type: str = ""
    finding: str | None = None
    content: str = ""
    date: str = ""
    tags: list[str] = Field(default_factory=list)


class WorkspaceLoot(PentNoteModel):
    """Loot record persisted in workspace state."""

    id: str = ""
    type: str = ""
    host: str = ""
    value: str | None = None
    path: str | None = None
    user: str | None = None
    date: str = ""
    notes: str = ""
    tags: list[str] = Field(default_factory=list)


class WorkspaceLog(PentNoteModel):
    """Attack log record persisted in workspace state."""

    id: str = ""
    message: str = ""
    date: str = ""
    source: str = "manual"
    host: str | None = None
    tags: list[str] = Field(default_factory=list)
    linked_finding_hash: str | None = None


class WorkspaceState(PentNoteModel):
    """Complete workspace JSON state."""

    credentials: list[WorkspaceCredential] = Field(default_factory=list)
    notes: list[WorkspaceNote] = Field(default_factory=list)
    loot: list[WorkspaceLoot] = Field(default_factory=list)
    log: list[WorkspaceLog] = Field(default_factory=list)
    pending_review: list[dict[str, Any]] = Field(default_factory=list)
    quality_stats: dict[str, Any] = Field(default_factory=dict)


class CanvasWriteResult(PentNoteModel):
    """Result of writing an Obsidian Canvas graph."""

    written: Path
    missing_notes: list[Any] = Field(default_factory=list)


class GhostLogSession(PentNoteModel):
    """Ghost Log daemon session counters."""

    started_at: datetime
    stopped_at: datetime | None = None
    commands_seen: int = 0
    commands_kept: int = 0
    credentials_found: int = 0
    findings_found: int = 0
    log_entries_found: int = 0
    last_command: str | None = None
    last_command_at: datetime | None = None
    total_sessions: int = 0
    cumulative_commands_seen: int = 0
    cumulative_commands_kept: int = 0
    cumulative_credentials: int = 0
    cumulative_findings: int = 0
    cumulative_log_entries: int = 0
    session_history: list[dict[str, Any]] = Field(default_factory=list)

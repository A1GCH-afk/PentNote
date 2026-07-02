from __future__ import annotations

from pentnote.models import (
    Credential,
    DomainObject,
    Finding,
    Host,
    MitreMatch,
    NetworkPath,
    ParsedResult,
    Port,
    Severity,
    WorkspaceState,
)


def test_models_instantiate_exact_phase_one_contract() -> None:
    match = MitreMatch("T1046", "Network Service Discovery", "Discovery", 1.0, "rule")
    finding = Finding(
        title="Open SMB",
        severity=Severity.INFO,
        mitre_matches=[match],
        affected_hosts=["192.168.56.10"],
        evidence="445/tcp open microsoft-ds",
        next_steps=["Validate SMB signing"],
        defenses=["D3-SFA"],
        chain_member=None,
        hash="abc123",
    )
    host = Host(
        ip="192.168.56.10",
        hostname="dc01.lab.local",
        os=None,
        ports=[Port(445, "tcp", "microsoft-ds", "Windows Server 2019", "open")],
        tags=["smb"],
    )
    credential = Credential(
        username="administrator",
        secret="aad3b435b51404eeaad3b435b51404ee",
        secret_type="ntlm",
        source_host="192.168.56.10",
        domain="LAB",
    )
    domain_object = DomainObject(
        name="Domain Admins",
        object_type="group",
        domain="lab.local",
        properties={"admin_count": True},
        paths=[NetworkPath("user", "group", "MemberOf")],
    )

    result = ParsedResult(
        tool="nmap",
        partial=False,
        hosts=[host],
        credentials=[credential],
        findings=[finding],
        domain_objects=[domain_object],
        raw_text="raw",
    )

    assert result.findings[0].mitre_matches[0].technique_id == "T1046"
    assert result.hosts[0].ports[0].number == 445
    assert result.credentials[0].cracked is False


def test_pydantic_models_ignore_extra_and_strip_strings() -> None:
    credential = Credential.model_validate(
        {
            "username": " alice ",
            "secret": " hash ",
            "secret_type": " ntlm ",
            "source_host": " 10.10.10.10 ",
            "domain": " LAB ",
            "unexpected": "ignored",
        }
    )

    assert credential.username == "alice"
    assert credential.secret == "hash"
    assert not hasattr(credential, "unexpected")


def test_workspace_state_ingests_legacy_json() -> None:
    state = WorkspaceState.model_validate(
        {
            "credentials": [
                {
                    "id": "cred-1",
                    "username": "alice",
                    "domain": "LAB",
                    "secret": "hash",
                    "secret_type": "ntlm",
                    "legacy_field": "ignored",
                }
            ],
            "notes": [],
            "loot": [],
            "log": [],
            "old_top_level": [],
        }
    )

    dumped = state.model_dump(mode="json")
    assert dumped["credentials"][0]["username"] == "alice"
    assert "legacy_field" not in dumped["credentials"][0]
    assert "old_top_level" not in dumped

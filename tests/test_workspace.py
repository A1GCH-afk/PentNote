from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from pentnote.cli import main
from pentnote.core.cracking import import_hashcat_potfile
from pentnote.core.engagement import init_engagement, load_engagement
from pentnote.mitre.next_steps import get_credential_next_steps
from pentnote.workspace.store import (
    WorkspaceStore,
    credential_id,
    record_unsupported_tool,
)


def _init_workspace(tmp_path: Path) -> WorkspaceStore:
    init_engagement(tmp_path, "Client", ["10.10.10.10"])
    return WorkspaceStore(tmp_path)


def _credential(username: str = "Administrator", secret_type: str = "ntlm") -> dict:
    return {
        "id": credential_id(username, "CORP", secret_type),
        "username": username,
        "domain": "CORP",
        "secret": "aad3b435b51404eeaad3b435b51404ee",
        "secret_type": secret_type,
        "source_host": "10.10.10.10",
        "source_tool": "impacket-secretsdump",
        "cracked": False,
        "cracked_value": None,
        "tags": [],
        "notes": "",
    }


def test_workspace_store_creates_on_first_use(tmp_path: Path) -> None:
    store = _init_workspace(tmp_path)

    assert store.load() == {"credentials": [], "notes": [], "loot": [], "log": []}


def test_workspace_store_atomic_write(tmp_path: Path) -> None:
    store = _init_workspace(tmp_path)
    store.save({"credentials": [], "notes": [], "loot": [], "log": []})

    assert store.path.exists()
    assert not store.path.with_suffix(".json.tmp").exists()


def test_add_credential_deduplication(tmp_path: Path) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    store.add_credential(_credential())

    assert len(store.get_credentials({})) == 1


def test_creds_add_manual_hash(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        main,
        [
            "creds",
            "add",
            "wacky",
            "--secret",
            "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca",
            "--type",
            "sha256",
            "--host",
            "wingdata",
            "--tag",
            "manual",
            "--notes",
            "Hash for Wacky user",
        ],
    )

    assert result.exit_code == 0, result.output
    credential = store.get_credentials({})[0]
    assert credential["username"] == "wacky"
    assert credential["secret_type"] == "sha256"
    assert credential["source_host"] == "wingdata"
    assert credential["source_tool"] == "manual"
    assert credential["tags"] == ["manual"]


def test_creds_add_sha256_type_accepted(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "add",
            "wacky",
            "--secret",
            "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca",
            "--type",
            "sha256",
            "--host",
            "wingdata",
        ],
    )

    assert result.exit_code == 0, result.output
    assert store.get_credentials({})[0]["secret_type"] == "sha256"


def test_creds_add_net_ntlmv2_type_accepted(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "add",
            "brandon.stark",
            "--secret",
            "brandon.stark::NORTH:abc123:HASH_DATA",
            "--type",
            "netntlmv2",
            "--host",
            "192.168.56.11",
        ],
    )

    assert result.exit_code == 0, result.output
    assert store.get_credentials({})[0]["secret_type"] == "net-ntlmv2"


def test_creds_secret_type_alias_ntlm(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "add",
            "administrator",
            "--secret",
            "aad3b435b51404eeaad3b435b51404ee",
            "--type",
            "NT",
            "--host",
            "10.10.10.10",
        ],
    )

    assert result.exit_code == 0, result.output
    assert store.get_credentials({})[0]["secret_type"] == "ntlm"


def test_creds_secret_type_alias_password_to_plaintext(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "add",
            "arya",
            "--secret",
            "Needle123!",
            "--type",
            "password",
            "--host",
            "winterfell",
        ],
    )

    assert result.exit_code == 0, result.output
    assert store.get_credentials({})[0]["secret_type"] == "plaintext"


def test_creds_unknown_secret_type_is_preserved(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "add",
            "samwell",
            "--secret",
            "customhash",
            "--type",
            "weird-hash",
            "--host",
            "castle-black",
        ],
    )

    assert result.exit_code == 0, result.output
    assert store.get_credentials({})[0]["secret_type"] == "weird-hash"


def test_creds_list_filter_by_type(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential(secret_type="ntlm"))
    store.add_credential(_credential("svc_backup", "kerberos"))
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["creds", "list", "--type", "kerberos"])

    assert result.exit_code == 0, result.output
    assert "svc_backup" in result.output
    assert "Administrator" not in result.output


def test_creds_export_hashcat_format(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["creds", "export", "--format", "hashcat"])

    assert "# hashcat -m 1000 hashes.txt rockyou.txt" in result.output
    assert "Administrator:aad3b435b51404eeaad3b435b51404ee" in result.output


def test_creds_export_hashcat_includes_mode_comment(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    cred = _credential("wacky", "sha256")
    cred["secret"] = "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca"
    store.add_credential(cred)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main, ["creds", "export", "--format", "hashcat", "--type", "sha256"]
    )

    assert result.exit_code == 0, result.output
    assert "# hashcat -m 1400 hashes.txt rockyou.txt" in result.output
    assert (
        "wacky:32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca"
        in result.output
    )


def test_creds_export_hashcat_includes_manual_sha256(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    cred = _credential("wacky", "sha256")
    cred["domain"] = None
    cred["secret"] = "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca"
    cred["source_tool"] = "manual"
    store.add_credential(cred)
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        main, ["creds", "export", "--format", "hashcat", "--type", "sha256"]
    )

    assert result.exit_code == 0, result.output
    assert (
        "wacky:32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca"
        in result.output
    )


def test_creds_export_prints_hashcat_guidance(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    output = tmp_path / "ntlm.txt"
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "export",
            "--format",
            "hashcat",
            "--type",
            "ntlm",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Hashcat Guidance:" in result.output
    assert "Sync cracked hashes:" in result.output


def test_creds_export_guidance_correct_mode_ntlm(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    output = tmp_path / "ntlm.txt"
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "export",
            "--format",
            "hashcat",
            "--type",
            "ntlm",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Mode:     -m 1000" in result.output
    assert "hashcat --username -m 1000" in result.output


def test_creds_export_guidance_correct_mode_netntlmv2(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    cred = _credential("brandon.stark", "net-ntlmv2")
    cred["secret"] = "brandon.stark::NORTH:abc123:HASH_DATA"
    store.add_credential(cred)
    output = tmp_path / "netntlmv2.txt"
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "creds",
            "export",
            "--format",
            "hashcat",
            "--type",
            "net-ntlmv2",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Mode:     -m 5600" in result.output
    assert "Net-NTLMv2" in result.output


def test_creds_crack_status_shows_counts(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    cracked = _credential()
    cracked["cracked"] = True
    cracked["cracked_value"] = "Password123!"
    store.add_credential(cracked)
    store.add_credential(_credential("svc_backup", "net-ntlmv2"))
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["creds", "crack-status"])

    assert result.exit_code == 0, result.output
    assert "Total credentials:   2" in result.output
    assert "Cracked:             1  (50%)" in result.output
    assert "Uncracked:           1" in result.output


def test_creds_crack_status_shows_by_type_breakdown(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    cracked = _credential()
    cracked["cracked"] = True
    store.add_credential(cracked)
    store.add_credential(_credential("svc_backup", "net-ntlmv2"))
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["creds", "crack-status"])

    assert result.exit_code == 0, result.output
    assert "By type:" in result.output
    assert "ntlm         1 total, 1 cracked (100%)" in result.output
    assert "net-ntlmv2   1 total, 0 cracked (0%)" in result.output


def test_creds_crack_status_shows_uncracked_command(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential("svc_backup", "net-ntlmv2"))
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["creds", "crack-status"])

    assert result.exit_code == 0, result.output
    assert "Uncracked hashes ready to export:" in result.output
    assert (
        "pentnote creds export --format hashcat --type net-ntlmv2 "
        "--output net-ntlmv2_remaining.txt"
    ) in result.output


def test_creds_unknown_type_gets_generic_next_steps() -> None:
    steps = get_credential_next_steps(
        username="jon",
        secret="abcdef1234567890abcdef1234567890",
        secret_type="custom-hash",
        host="10.10.10.10",
        domain="NORTH",
    )

    assert steps == [
        "Identify hash type: hashid abcdef1234567890abcd...",
        "Try hashcat auto-detect: hashcat -a 0 hash.txt rockyou.txt",
        "Try john: john --format=auto hash.txt",
    ]


def test_creds_export_wordlist_format(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["creds", "export", "--format", "wordlist"])

    assert result.output.strip() == "Administrator"


def test_creds_export_spray_format(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    cred = _credential("alice", "plaintext")
    cred["secret"] = "Password123!"
    store.add_credential(cred)
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["creds", "export", "--format", "spray"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "alice:Password123!"


def test_creds_update_cracked(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        main,
        ["creds", "update", "Administrator", "--cracked", "P@ssw0rd123"],
    )

    assert result.exit_code == 0, result.output
    cred = store.get_credentials({})[0]
    assert cred["cracked"] is True
    assert cred["cracked_value"] == "P@ssw0rd123"


def test_import_hashcat_potfile_updates_workspace_and_note(tmp_path: Path) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    note = tmp_path / "notes" / "credentials" / "corp-administrator.md"
    note.parent.mkdir(parents=True)
    note.write_text(
        "---\ntags: [credential, ntlm]\n---\n\n"
        "# Credential - Administrator\n\n"
        "## Details\n"
        "| Field | Value |\n"
        "| --- | --- |\n"
        "| Cracked | ✗ |\n\n"
        "## Notes\n",
        encoding="utf-8",
    )
    potfile = tmp_path / "hashcat.potfile"
    potfile.write_text(
        "aad3b435b51404eeaad3b435b51404ee:P@ssw0rd123\n",
        encoding="utf-8",
    )

    engagement = load_engagement(tmp_path)
    result = import_hashcat_potfile(str(potfile), engagement=engagement)

    credential = store.load()["credentials"][0]
    assert result.updated == 1
    assert credential["cracked"] is True
    assert credential["cracked_value"] == "P@ssw0rd123"
    assert credential["plaintext"] == "P@ssw0rd123"
    note_text = note.read_text(encoding="utf-8")
    assert "cracked" in note_text
    assert "✅ CRACKED" in note_text
    assert "Credential cracked" in (tmp_path / "notes" / "TIMELINE.md").read_text()


def test_creds_sync_pot_cli(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_credential(_credential())
    potfile = tmp_path / "hashcat.potfile"
    potfile.write_text(
        "aad3b435b51404eeaad3b435b51404ee:P@ssw0rd123\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["creds", "sync-pot", str(potfile)])

    assert result.exit_code == 0, result.output
    assert "updated=1" in result.output
    assert store.load()["credentials"][0]["cracked"] is True


def test_note_add_to_host(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["note", "add", "10.10.10.10", "Login page"])

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert data["notes"][0]["target_type"] == "host"


def test_note_appended_to_md_file(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    host_note = tmp_path / "notes" / "hosts" / "10-10-10-10.md"
    host_note.parent.mkdir(parents=True)
    host_note.write_text("# 10.10.10.10\n\n## Notes\n<!-- analyst notes here -->\n")
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["note", "add", "10.10.10.10", "Got shell"])

    assert result.exit_code == 0, result.output
    assert "Got shell" in host_note.read_text()


def test_note_list_filter_by_host(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    runner.invoke(main, ["note", "add", "10.10.10.10", "host note"])
    runner.invoke(main, ["note", "add", "10.10.10.11", "other note"])

    result = runner.invoke(main, ["note", "list", "--host", "10.10.10.10"])

    assert "#" in result.output
    assert "1" in result.output
    assert "─" in result.output
    assert "host note" in result.output
    assert "other note" not in result.output


def test_note_list_keeps_oldest_note_as_number_one(tmp_path: Path, monkeypatch) -> None:
    store = _init_workspace(tmp_path)
    store.add_note(
        {
            "id": "old",
            "target": "10.10.10.10",
            "target_type": "host",
            "finding": None,
            "content": "oldest note",
            "date": "2026-04-28T10:00:00+00:00",
            "tags": [],
        }
    )
    store.add_note(
        {
            "id": "new",
            "target": "10.10.10.10",
            "target_type": "host",
            "finding": None,
            "content": "newest note",
            "date": "2026-04-28T11:00:00+00:00",
            "tags": [],
        }
    )
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["note", "list"])

    assert result.exit_code == 0, result.output
    assert result.output.find("oldest note") < result.output.find("newest note")


def test_note_delete_removes_note_by_visible_number(
    tmp_path: Path, monkeypatch
) -> None:
    store = _init_workspace(tmp_path)
    store.add_note(
        {
            "id": "old",
            "target": "10.10.10.10",
            "target_type": "host",
            "finding": None,
            "content": "oldest note",
            "date": "2026-04-28T10:00:00+00:00",
            "tags": [],
        }
    )
    store.add_note(
        {
            "id": "new",
            "target": "10.10.10.10",
            "target_type": "host",
            "finding": None,
            "content": "newest note",
            "date": "2026-04-28T11:00:00+00:00",
            "tags": [],
        }
    )
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["note", "delete", "1"])

    assert result.exit_code == 0, result.output
    assert [item["content"] for item in store.get_notes({})] == ["newest note"]


def test_loot_add_flag(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "loot",
            "add",
            "--type",
            "flag",
            "--value",
            "HTB{abc}",
            "--host",
            "10.10.10.10",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert data["loot"][0]["type"] == "flag"


def test_loot_summary_counts(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    runner.invoke(
        main,
        [
            "loot",
            "add",
            "--type",
            "flag",
            "--value",
            "HTB{abc}",
            "--host",
            "10.10.10.10",
        ],
    )

    result = runner.invoke(main, ["loot", "summary"])

    assert "Flags captured:" in result.output
    assert "1" in result.output


def test_loot_written_to_loot_md(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    runner.invoke(
        main,
        [
            "loot",
            "add",
            "--type",
            "file",
            "--path",
            "/etc/passwd",
            "--host",
            "10.10.10.10",
        ],
    )

    assert "/etc/passwd" in (tmp_path / "notes" / "LOOT.md").read_text()


def _add_loot(runner: CliRunner, *args: str) -> None:
    runner.invoke(main, ["loot", "add", *args])


def _loot_ids(tmp_path: Path) -> list[str]:
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    return [item["id"] for item in data["loot"]]


def test_loot_list_displays_short_id(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(runner, "--type", "flag", "--value", "HTB{a}", "--host", "10.10.10.10")

    result = runner.invoke(main, ["loot", "list"])

    assert result.exit_code == 0, result.output
    assert _loot_ids(tmp_path)[0][:8] in result.output


def test_loot_remove_by_id(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(runner, "--type", "flag", "--value", "HTB{a}", "--host", "10.10.10.10")
    short_id = _loot_ids(tmp_path)[0][:8]

    result = runner.invoke(main, ["loot", "remove", short_id, "--yes"])

    assert result.exit_code == 0, result.output
    assert "Loot removed" in result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert data["loot"] == []


def test_loot_remove_last(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(runner, "--type", "flag", "--value", "first", "--host", "10.10.10.10")
    _add_loot(
        runner,
        "--type",
        "secret",
        "--value",
        "second",
        "--host",
        "10.10.10.10",
        "--user",
        "svc",
    )

    result = runner.invoke(main, ["loot", "remove", "--last", "--yes"])

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert [item["value"] for item in data["loot"]] == ["first"]


def test_loot_remove_nonexistent_id_fails(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(runner, "--type", "flag", "--value", "HTB{a}", "--host", "10.10.10.10")

    result = runner.invoke(main, ["loot", "remove", "nonexistent", "--yes"])

    assert result.exit_code != 0
    assert "No loot entry" in result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert len(data["loot"]) == 1


def test_loot_remove_requires_confirmation(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(runner, "--type", "flag", "--value", "HTB{a}", "--host", "10.10.10.10")
    short_id = _loot_ids(tmp_path)[0][:8]

    result = runner.invoke(main, ["loot", "remove", short_id], input="n\n")

    assert result.exit_code == 0, result.output
    assert "Aborted" in result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert len(data["loot"]) == 1


def test_loot_list_filter_by_user(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(
        runner, "--type", "secret", "--value", "s1", "--host", "h", "--user", "admin"
    )
    _add_loot(
        runner, "--type", "secret", "--value", "s2", "--host", "h", "--user", "guest"
    )

    result = runner.invoke(main, ["loot", "list", "--user", "admin"])

    assert result.exit_code == 0, result.output
    assert "s1" in result.output
    assert "s2" not in result.output


def test_loot_summary_filter_by_user(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    _add_loot(
        runner, "--type", "hash", "--value", "h1", "--host", "h", "--user", "admin"
    )
    _add_loot(
        runner, "--type", "hash", "--value", "h2", "--host", "h", "--user", "guest"
    )

    result = runner.invoke(main, ["loot", "summary", "--user", "admin"])

    assert result.exit_code == 0, result.output
    assert "Hashes collected: 1" in result.output


def test_record_unsupported_tool_creates_host_note(tmp_path: Path) -> None:
    notes = tmp_path / "notes"

    path = record_unsupported_tool(
        notes, "10.0.0.9", "hydra", "hydra -l admin 10.0.0.9 ssh"
    )

    text = path.read_text(encoding="utf-8")
    assert "## Unparsed / Unsupported Tools" in text
    assert "hydra" in text
    assert "hydra -l admin 10.0.0.9 ssh" in text
    assert text.rstrip().endswith("<!-- analyst notes here -->")


def test_record_unsupported_tool_appends_without_duplicating_heading(
    tmp_path: Path,
) -> None:
    notes = tmp_path / "notes"
    record_unsupported_tool(notes, "10.0.0.9", "hydra", "cmd1")

    path = record_unsupported_tool(notes, "10.0.0.9", "faketime", "cmd2")

    text = path.read_text(encoding="utf-8")
    assert text.count("## Unparsed / Unsupported Tools") == 1
    assert "hydra" in text
    assert "faketime" in text


def test_log_add_entry(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, ["log", "Tried SMB relay"])

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert data["log"][0]["message"] == "Tried SMB relay"


def test_log_appended_to_timeline(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    runner.invoke(main, ["log", "Got RCE", "--host", "10.10.10.10"])

    timeline = (tmp_path / "notes" / "TIMELINE.md").read_text()

    assert "Got RCE" in timeline
    assert "| manual | Got RCE" in timeline


def test_log_list_filter_today(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    runner.invoke(main, ["log", "Today entry", "--tag", "pivot"])

    result = runner.invoke(main, ["log", "list", "--today"])

    assert "Today entry" in result.output


def test_flag_loot_auto_logs(tmp_path: Path, monkeypatch) -> None:
    _init_workspace(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    runner.invoke(
        main,
        [
            "loot",
            "add",
            "--type",
            "flag",
            "--value",
            "HTB{abc}",
            "--host",
            "10.10.10.10",
        ],
    )

    data = json.loads((tmp_path / ".pentnote" / "workspace.json").read_text())
    assert any("Flag captured" in entry["message"] for entry in data["log"])

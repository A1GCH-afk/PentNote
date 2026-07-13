from __future__ import annotations

import os
from pathlib import Path

import pytest
from pentnote.generators.index import write_index
from pentnote.generators.markdown import (
    _credential_path,
    _domain_path,
    _finding_path,
    _short_title,
    render_credential_markdown,
    render_finding_markdown,
    render_host_markdown,
    slugify,
    write_result_markdown,
    write_tool_index,
)
from pentnote.generators.report import (
    _arc_path,
    build_donut_chart_data,
    build_tactic_bars,
    write_report,
)
from pentnote.generators.timeline import write_timeline
from pentnote.mitre.next_steps import get_credential_next_steps
from pentnote.models import (
    Credential,
    DomainObject,
    Finding,
    Host,
    MitreMatch,
    ParsedResult,
    Port,
    Severity,
    WorkspaceLoot,
)
from pentnote.parsers.v1.crackmapexec import CrackMapExecParser
from pentnote.parsers.v1.nmap import NmapParser
from pentnote.parsers.v15.bloodhound import BloodHoundParser

FIXTURES = Path(__file__).parent / "fixtures"


def _sample_finding(
    title: str,
    finding_hash: str = "abc123def456",
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.INFO,
        mitre_matches=[],
        affected_hosts=["kobold.htb"],
        evidence=title,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=finding_hash,
    )


def test_render_host_markdown_uses_template_sections() -> None:
    result = NmapParser().parse((FIXTURES / "nmap_sample.xml").read_text())

    markdown = render_host_markdown(
        result.hosts[0],
        engagement_name="Client_2026",
        tool_name="nmap",
        iso_timestamp="2026-04-26T00:00:00+00:00",
    )

    assert "## Target Info" in markdown
    assert "## Open Ports" in markdown
    assert "10.129.48.183" in markdown


def test_write_result_markdown_writes_host_note(tmp_path: Path) -> None:
    result = NmapParser().parse((FIXTURES / "nmap_sample.xml").read_text())

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written == [tmp_path / "hosts" / "10-129-48-183.md"]
    assert written[0].exists()


def test_host_note_regeneration_preserves_unsupported_tools_section(
    tmp_path: Path,
) -> None:
    from pentnote.workspace.store import record_unsupported_tool

    host = Host(ip="10.0.0.9", ports=[])
    write_result_markdown(
        ParsedResult(tool="nmap", hosts=[host]), tmp_path, engagement_name="E"
    )
    record_unsupported_tool(tmp_path, "10.0.0.9", "hydra", "hydra 10.0.0.9")

    # A later supported-tool parse regenerates the note from the template.
    write_result_markdown(
        ParsedResult(tool="nmap", hosts=[host]), tmp_path, engagement_name="E"
    )

    text = (tmp_path / "hosts" / "10-0-0-9.md").read_text(encoding="utf-8")
    assert "## Open Ports" in text  # full note rendered
    assert text.count("## Unparsed / Unsupported Tools") == 1  # section preserved once
    assert "hydra" in text
    assert text.rstrip().endswith("<!-- analyst notes here -->")  # Notes stays last


def test_host_note_write_survives_interrupted_rename(
    tmp_path: Path, monkeypatch
) -> None:
    """An interrupted host-note write must not truncate the existing note.

    Host notes are read-modify-written on every merge; a crash mid-write used
    to leave a truncated/empty note (silent data loss). The atomic temp+rename
    path keeps the prior complete note intact if the rename never lands.
    """

    write_result_markdown(
        ParsedResult(
            tool="nmap",
            hosts=[Host(ip="10.0.0.5", ports=[Port(22, "tcp", "ssh", "v", "open")])],
        ),
        tmp_path,
        engagement_name="E",
    )
    note = tmp_path / "hosts" / "10-0-0-5.md"
    original = note.read_text()

    real_replace = os.replace

    def boom_replace(src, dst):
        if Path(dst).name == "10-0-0-5.md":
            raise OSError("crash during rename")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        write_result_markdown(
            ParsedResult(
                tool="nmap",
                hosts=[
                    Host(ip="10.0.0.5", ports=[Port(80, "tcp", "http", "v", "open")])
                ],
            ),
            tmp_path,
            engagement_name="E",
        )

    assert note.read_text() == original  # prior complete note survived


def test_host_note_merge_is_case_insensitive_for_hostname(tmp_path: Path) -> None:
    """Item 1 (case-insensitive): the same hostname in a different case is the
    same host, not a superseded name to demote into an alias."""

    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.5", hostname="DC01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )
    write_result_markdown(
        ParsedResult(
            tool="crackmapexec", hosts=[Host(ip="10.0.0.5", hostname="dc01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )

    note = (tmp_path / "hosts" / "10-0-0-5.md").read_text()
    assert "Also Known As" not in note  # no spurious case-variant alias


def test_resolve_host_note_merges_on_data_backed_link_not_hostname_string(
    tmp_path: Path,
) -> None:
    """Item 1 (positive): auto-merge requires a data-backed link -- an IP
    identity, or a hostname match corroborated by a matching ``known_ip``.
    Both still merge (case-insensitively); a bare hostname string does not."""

    from pentnote.workspace.store import resolve_host_note_path

    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.5", hostname="DC01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )

    # Network-layer identity: an incoming IP equal to the note's host: merges.
    path, warning = resolve_host_note_path(tmp_path, "10.0.0.5")
    assert path.name == "10-0-0-5.md"
    assert warning is None

    # Corroborated hostname: the hostname a tool tied to this IP, supplied with a
    # matching known_ip, is a confirmed link -> merges, case-insensitively.
    for reference in ("DC01", "dc01"):
        path, warning = resolve_host_note_path(tmp_path, reference, known_ip="10.0.0.5")
        assert path.name == "10-0-0-5.md", reference
        assert warning is None, reference


def test_resolve_host_note_identical_hostname_different_host_does_not_merge(
    tmp_path: Path,
) -> None:
    """Item 1 (negative -- the case the audit required): two different hosts that
    share an identical hostname string must NOT auto-merge. A reused NetBIOS/host
    name (cloned image, default name, DC pair) is not proof of one host, so a
    bare-name match -- or one with a non-matching known_ip -- stays separate."""

    from pentnote.workspace.store import resolve_host_note_path

    # Host A: 10.0.0.5, tool-captured hostname SRV01.
    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.5", hostname="SRV01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )

    # A genuinely different host also named SRV01, referenced by bare name with
    # no corroborating IP, must land on a fresh note -- not host A's.
    path, warning = resolve_host_note_path(tmp_path, "srv01")
    assert path.name == "srv01.md"
    assert warning is not None
    assert "possible duplicate" in warning

    # A supplied but mismatched known_ip does not authorize the merge either.
    path, warning = resolve_host_note_path(tmp_path, "srv01", known_ip="10.0.0.9")
    assert path.name == "srv01.md"
    assert warning is not None


def test_resolve_host_note_unconfirmed_link_stays_separate_and_warns(
    tmp_path: Path,
) -> None:
    """Item 1: a plausible-but-unconfirmed match (shared first label only) is
    never auto-merged -- it returns a fresh path plus a warning to reconcile."""

    from pentnote.workspace.store import resolve_host_note_path

    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.5", hostname="DC01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )

    path, warning = resolve_host_note_path(tmp_path, "DC01.OTHER.LOCAL")

    assert path.name == "dc01-other-local.md"  # separate note, not merged
    assert warning is not None
    assert "possible duplicate" in warning


def test_record_unsupported_tool_surfaces_possible_duplicate_warning(
    tmp_path: Path, capsys
) -> None:
    """Item 1: an unconfirmed match reached through a real write path warns on
    stderr and creates a separate note instead of silently wrong-merging."""

    from pentnote.workspace.store import record_unsupported_tool

    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.5", hostname="DC01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )

    record_unsupported_tool(tmp_path, "DC01.OTHER.LOCAL", "hydra", "hydra x")
    captured = capsys.readouterr()

    assert "possible duplicate" in captured.err
    assert (tmp_path / "hosts" / "dc01-other-local.md").exists()  # stayed separate


def test_find_suspected_host_merges_flags_shared_hostname_different_ip(
    tmp_path: Path,
) -> None:
    """Detection (SHOULD flag): two genuinely different hosts that share a
    hostname string but sit at different IPs are exactly what the pre-1.1.0 rule
    would have string-merged. The read-only check must surface both notes."""

    from pentnote.workspace.store import find_suspected_host_merges

    for ip in ("10.0.0.5", "10.0.0.9"):
        write_result_markdown(
            ParsedResult(tool="nmap", hosts=[Host(ip=ip, hostname="SRV01", ports=[])]),
            tmp_path,
            engagement_name="E",
        )

    flagged = find_suspected_host_merges(tmp_path)

    assert {s.note_path.name for s in flagged} == {"10-0-0-5.md", "10-0-0-9.md"}
    assert all(s.confidence == "high" for s in flagged)  # exact-name collision
    # Each note names the other as its colliding counterpart.
    a = next(s for s in flagged if s.note_path.name == "10-0-0-5.md")
    assert any("10-0-0-9.md" in c for c in a.collisions)


def test_find_suspected_host_merges_ignores_data_backed_distinct_hosts(
    tmp_path: Path,
) -> None:
    """Detection (should NOT flag): a legitimate data-backed merge under the new
    rule -- one host whose second observation (same IP) added an alias -- plus a
    genuinely distinct host with its own name, produce no name collisions."""

    from pentnote.workspace.store import find_suspected_host_merges

    # Data-backed same-host merge: two observations at ONE IP fold into one note
    # (DC01 + DC01.CORP.LOCAL alias) -- correct, IP-linked, not a conflation.
    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.5", hostname="DC01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )
    write_result_markdown(
        ParsedResult(
            tool="crackmapexec",
            hosts=[Host(ip="10.0.0.5", hostname="DC01.CORP.LOCAL", ports=[])],
        ),
        tmp_path,
        engagement_name="E",
    )
    # A separate, unrelated host with a distinct name.
    write_result_markdown(
        ParsedResult(
            tool="nmap", hosts=[Host(ip="10.0.0.9", hostname="WEB01", ports=[])]
        ),
        tmp_path,
        engagement_name="E",
    )

    assert find_suspected_host_merges(tmp_path) == []


def test_same_tool_rerun_merges_open_ports_by_port_key_without_duplicates(
    tmp_path: Path,
) -> None:
    """Re-running the SAME tool against a host must row-merge the Open Ports table.

    Regression guard for same-tool-rerun row loss/duplication: a second nmap run
    (e.g. after widening scope) must update a changed row in place keyed by the
    port's natural key, append genuinely new ports, and never drop the earlier
    run's ports or emit duplicate rows for a port already listed.
    """

    first = ParsedResult(
        tool="nmap",
        hosts=[
            Host(
                ip="10.0.0.5",
                ports=[
                    Port(22, "tcp", "ssh", "OpenSSH 8.0", "open"),
                    Port(80, "tcp", "http", "Apache 2.4.1", "open"),
                ],
            )
        ],
    )
    second = ParsedResult(
        tool="nmap",
        hosts=[
            Host(
                ip="10.0.0.5",
                ports=[
                    Port(80, "tcp", "http", "Apache 2.4.62", "open"),  # changed
                    Port(443, "tcp", "https", "nginx 1.25", "open"),  # new
                ],
            )
        ],
    )

    write_result_markdown(first, tmp_path, engagement_name="E")
    write_result_markdown(second, tmp_path, engagement_name="E")

    note = (tmp_path / "hosts" / "10-0-0-5.md").read_text()
    port_rows = [
        line
        for line in note.splitlines()
        if line.startswith("| ") and line.split("|")[1].strip().isdigit()
    ]

    # No duplicate rows for a port already present.
    assert sum(row.split("|")[1].strip() == "80" for row in port_rows) == 1
    # Earlier run's port retained, new port appended.
    assert any(row.split("|")[1].strip() == "22" for row in port_rows)
    assert any(row.split("|")[1].strip() == "443" for row in port_rows)
    # Changed row updated in place with the newer version.
    assert "Apache 2.4.62" in note
    assert "Apache 2.4.1" not in note


def test_write_result_markdown_merges_existing_host_ports(tmp_path: Path) -> None:
    smb = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[
            Host(
                ip="192.168.56.11",
                hostname="WINTERFELL",
                os="Windows Server 2019 x64",
                ports=[Port(445, "tcp", "smb", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    ldap = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[
            Host(
                ip="192.168.56.11",
                hostname="WINTERFELL",
                os="Windows Server 2019",
                ports=[Port(389, "tcp", "ldap", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(smb, tmp_path, engagement_name="Client_2026")
    note_path = tmp_path / "hosts" / "192-168-56-11.md"
    note_path.write_text(
        note_path.read_text() + "\nmanual analyst note\n",
        encoding="utf-8",
    )
    write_result_markdown(ldap, tmp_path, engagement_name="Client_2026")

    note = note_path.read_text()
    assert "| 389 | tcp | ldap | N/A | open |" in note
    assert "| 445 | tcp | smb | N/A | open |" in note
    assert "manual analyst note" in note


def test_write_result_markdown_cross_tool_write_does_not_clobber_prior_tool_data(
    tmp_path: Path,
) -> None:
    """A second tool writing the same host note must not overwrite the first tool's data.

    Root cause: `_merge_existing_host_note` used to rebuild the host's `Host`
    object from scratch, forwarding only `ports`. Every other field --
    `hostname`, `av_products`, and the frontmatter `tool` -- came solely from
    whichever tool ran most recently, silently discarding the previous tool's
    contribution instead of merging it. This reproduces that exact scenario:
    nmap discovers a host under a DNS alias with open ports, then crackmapexec
    resolves its real AD hostname and AV product on the same IP.
    """

    nmap_result = NmapParser().parse((FIXTURES / "nmap_sample.xml").read_text())
    ip = nmap_result.hosts[0].ip
    original_hostname = nmap_result.hosts[0].hostname
    assert original_hostname is not None

    write_result_markdown(nmap_result, tmp_path, engagement_name="Client_2026")
    note_path = tmp_path / "hosts" / f"{ip.replace('.', '-')}.md"

    cme_result = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[
            Host(
                ip=ip,
                hostname="DC01",
                os="Windows Server 2019 x64",
                ports=[],
                tags=[],
                av_products=["Windows Defender"],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    write_result_markdown(cme_result, tmp_path, engagement_name="Client_2026")

    note = note_path.read_text()

    # Both tools are tracked in frontmatter history, not just the last writer.
    assert "tools: [nmap, crackmapexec]" in note
    assert "tool: crackmapexec" in note

    # nmap's Open Ports table survives the crackmapexec write untouched.
    assert "| 22 | tcp | ssh | OpenSSH 9.2p1 Debian 2+deb12u7 | open |" in note
    assert "| 80 | tcp | http | Apache httpd 2.4.66 | open |" in note

    # crackmapexec's AD-resolved hostname wins, but nmap's alias is preserved.
    assert "hostname: DC01" in note
    assert f"| Also Known As | {original_hostname} |" in note

    # crackmapexec's Security Products contribution is present.
    assert "| Windows Defender | Detected |" in note


def test_write_result_markdown_same_tool_rerun_refreshes_its_own_hostname(
    tmp_path: Path,
) -> None:
    """A tool re-running must be able to correct its own previously-reported hostname.

    The hostname-priority rule exists to stop a *different* tool's generic
    alias from clobbering an already-resolved AD hostname. It must not also
    freeze a tool's own value in place: nmap resolving a corrected PTR record
    on a rescan should update the primary hostname, not get permanently
    demoted to an alias behind its own stale first guess.
    """

    ip = "10.6.6.6"
    first = ParsedResult(
        tool="nmap",
        partial=False,
        hosts=[
            Host(
                ip=ip,
                hostname="stale.htb",
                os=None,
                ports=[Port(22, "tcp", "ssh", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    second = ParsedResult(
        tool="nmap",
        partial=False,
        hosts=[
            Host(
                ip=ip,
                hostname="corrected.htb",
                os=None,
                ports=[Port(22, "tcp", "ssh", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(first, tmp_path, engagement_name="Client_2026")
    write_result_markdown(second, tmp_path, engagement_name="Client_2026")

    note = (tmp_path / "hosts" / f"{ip.replace('.', '-')}.md").read_text()
    assert "hostname: corrected.htb" in note
    assert "| Also Known As | stale.htb |" in note


def test_write_result_markdown_writes_credentials_findings_and_domain(
    tmp_path: Path,
) -> None:
    cme = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    bloodhound = BloodHoundParser().parse(
        (FIXTURES / "bloodhound_sample.json").read_text()
    )

    cme_paths = write_result_markdown(cme, tmp_path, engagement_name="Client_2026")
    domain_paths = write_result_markdown(
        bloodhound,
        tmp_path,
        engagement_name="Client_2026",
    )

    assert any("credentials" in str(path) for path in cme_paths)
    assert any("findings" in str(path) for path in cme_paths)
    assert any("domain" in str(path) for path in domain_paths)


def test_write_result_markdown_writes_loot_note_for_parsed_artifact(
    tmp_path: Path,
) -> None:
    """Parser-discovered artifacts must be written to a notes/loot/ note.

    Regression guard for the krb5 silent-drop: a ParsedResult carrying loot
    now produces a loot note under notes/loot/<type>/<slug>.md recording the
    artifact path, rather than the path vanishing after parsing.
    """

    result = ParsedResult(
        tool="crackmapexec",
        loot=[
            WorkspaceLoot(
                type="file",
                host="10.10.11.174",
                value="./krb5.conf",
                path="./krb5.conf",
                notes="krb5 conf (crackmapexec)",
            )
        ],
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    loot_note = tmp_path / "loot" / "file" / "krb5-conf.md"
    assert loot_note in written
    body = loot_note.read_text()
    assert "type: file" in body
    assert "| Path | ./krb5.conf |" in body
    assert "host: 10.10.11.174" in body


def test_finding_path_uses_tool_subfolder(tmp_path: Path) -> None:
    finding = _sample_finding("Web virtual host discovered: home.kobold.htb")

    path = _finding_path(finding, "gobuster", tmp_path)

    assert path == tmp_path / "findings" / "gobuster" / "home.md"


def test_finding_short_title_removes_tool_prefix() -> None:
    title = "Web virtual host discovered: home page.kobold.htb"

    short = _short_title(title, "gobuster")

    assert "gobuster" not in short
    assert len(short) <= 40


def test_finding_short_title_max_40_chars() -> None:
    title = "A very long finding title that exceeds the limit"

    short = _short_title(title, "nmap")

    assert len(slugify(short)) <= 40


def test_tool_index_created_after_parse(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[
            _sample_finding("Web virtual host discovered: home.kobold.htb"),
            _sample_finding("Web virtual host discovered: cgi-bin.kobold.htb"),
        ],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert (tmp_path / "findings" / "gobuster" / "_index.md").exists()


def test_tool_index_contains_all_findings(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[
            _sample_finding("Web virtual host discovered: home.kobold.htb"),
            _sample_finding("Web virtual host discovered: cgi-bin.kobold.htb"),
        ],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")
    index = (tmp_path / "findings" / "gobuster" / "_index.md").read_text()

    assert "[[home]]" in index
    assert "[[cgi-bin]]" in index


def test_tool_index_written_even_when_no_findings(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    index = tmp_path / "findings" / "gobuster" / "_index.md"
    assert index in written
    assert index.exists()


def test_tool_index_empty_shows_success_callout(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")
    index = (tmp_path / "findings" / "gobuster" / "_index.md").read_text()

    assert "[!success] Scan Completed - No Findings" in index


def test_tool_index_nonempty_shows_findings_table(tmp_path: Path) -> None:
    tool_dir = tmp_path / "findings" / "gobuster"
    tool_dir.mkdir(parents=True)
    write_tool_index(
        "gobuster",
        "target",
        [_sample_finding("Web path discovered: /admin")],
        tool_dir,
    )

    index = (tool_dir / "_index.md").read_text()

    assert "| Finding | Severity | MITRE |" in index
    assert "Scan Completed - No Findings" not in index


def test_tool_index_includes_raw_path(tmp_path: Path) -> None:
    tool_dir = tmp_path / "findings" / "gobuster"
    tool_dir.mkdir(parents=True)
    raw_path = tmp_path / "raw" / "gobuster.txt"

    write_tool_index("gobuster", "target", [], tool_dir, raw_path=raw_path)

    index = (tool_dir / "_index.md").read_text()
    assert str(raw_path) in index


def test_credential_path_ntlm_in_ntlm_folder(tmp_path: Path) -> None:
    credential = Credential("administrator", "HASH", "ntlm", "10.0.0.1", "LAB")

    path = _credential_path(credential, tmp_path)

    assert path == tmp_path / "credentials" / "ntlm" / "administrator.md"


def test_credential_path_plaintext_folder(tmp_path: Path) -> None:
    credential = Credential("brandon.stark", "pass", "plaintext", "10.0.0.1", "NORTH")

    path = _credential_path(credential, tmp_path)

    assert path == tmp_path / "credentials" / "plaintext" / "brandon-stark.md"


def test_domain_users_in_users_subfolder(tmp_path: Path) -> None:
    obj = DomainObject(name="john.doe", object_type="user", domain="north.local")

    path = _domain_path(obj, tmp_path)

    assert path == tmp_path / "domain" / "users" / "john-doe.md"


def test_finding_collision_adds_hash_suffix(tmp_path: Path) -> None:
    finding = _sample_finding("SMB Signing Disabled", finding_hash="abcdef123456")
    existing = tmp_path / "findings" / "cme" / "smb-signing-disabled.md"
    existing.parent.mkdir(parents=True)
    existing.write_text("---\nhash: different\n---\n", encoding="utf-8")

    path = _finding_path(finding, "cme", tmp_path)

    assert path.name == "smb-signing-disabled-abcdef.md"


def test_finding_note_filename_starts_with_readable_context(tmp_path: Path) -> None:
    finding = Finding(
        title="Web virtual host discovered: staging.silentium.htb",
        severity=Severity.LOW,
        mitre_matches=[],
        affected_hosts=["silentium.htb"],
        evidence="staging.silentium.htb Status: 200 [Size: 3142]",
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash="bd1bbab42d820f8fee869d29263bf8c66b0be19396f20859babf88d06eec8a46",
    )
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[finding],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written[0] == tmp_path / "findings" / "gobuster" / "staging.md"


def test_finding_note_filename_keeps_short_hash_suffix(tmp_path: Path) -> None:
    finding = Finding(
        title="SMB Signing Disabled",
        severity=Severity.HIGH,
        mitre_matches=[],
        affected_hosts=["192.168.56.11"],
        evidence="signing:False",
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash="abc123def4567890",
    )
    result = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[finding],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written[0] == (
        tmp_path / "findings" / "crackmapexec" / "smb-signing-disabled.md"
    )


def test_finding_note_filename_removes_duplicate_host_suffix(tmp_path: Path) -> None:
    finding = Finding(
        title="Web virtual host discovered: git-head.silentium.htb",
        severity=Severity.INFO,
        mitre_matches=[],
        affected_hosts=["silentium.htb"],
        evidence=".git/HEAD.silentium.htb Status: 400 [Size: 166]",
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash="b064560f92ae8009422da877144a9374",
    )
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[finding],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written[0] == tmp_path / "findings" / "gobuster" / "git-head.md"


def test_index_timeline_and_report_generators(tmp_path: Path) -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    index_path = write_index(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
        scope=["192.168.56.0/24"],
    )
    timeline_path = write_timeline(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
    )
    report_paths = write_report(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
        report_format="both",
        with_defenses=True,
    )

    assert "T1557.001" in index_path.read_text()
    assert "Administrative access confirmed" in timeline_path.read_text()
    assert len(report_paths) == 2


def test_finding_note_confidence_chain_and_defenses_are_polished() -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    markdown = render_credential_markdown(
        result.credentials[0],
        engagement_name="Client_2026",
        tool_name="crackmapexec",
        iso_timestamp="2026-04-27T20:10:23+00:00",
    )
    finding = result.findings[0]
    finding.mitre_matches = [
        MitreMatch("T1021.002", "SMB", "Lateral Movement", 0.4, "rule")
    ]
    finding.defenses = []
    rendered = render_finding_markdown(
        finding,
        engagement_name="Client_2026",
        tool_name="crackmapexec",
        hostname="DC01",
        iso_timestamp="2026-04-27T20:10:23+00:00",
    )

    assert "40%" in rendered
    assert "chain: null" not in rendered
    assert "| Technique | D3FEND ID | Description |" in rendered
    assert "hostname: DC01" in rendered
    assert "tags: [credential" in markdown


def test_report_has_summary_and_recommendations(tmp_path: Path) -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    report_paths = write_report(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        with_defenses=True,
    )
    report = report_paths[0].read_text()

    assert "## Executive Summary" in report
    assert "## Top 5 Risks" in report
    assert "#### Recommendations" in report


def test_report_has_executive_summary_section(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("Critical Risk", Severity.CRITICAL)]
    )

    assert "## Executive Summary" in report
    assert "| Critical | 1 |" in report


def test_report_empty_sections_use_one_consistent_marker(tmp_path: Path) -> None:
    report = _write_test_report(tmp_path, [])

    # Every empty list section uses the same marker; empty tables use all-N/A
    # rows (the same convention the host-note writer uses).
    for section in ("## Attack Chains Detected", "## Findings", "## Evidence Appendix"):
        assert section in report
    assert "None recorded." in report
    assert "| N/A | N/A |" in report
    # The retired, inconsistent markers must be gone.
    assert "None detected." not in report
    assert "No findings recorded." not in report
    assert "No evidence recorded." not in report


def test_report_section_order_is_stable_regardless_of_data(tmp_path: Path) -> None:
    ordered_sections = [
        "## Executive Summary",
        "## Attack Chains Detected",
        "## Top 5 Risks",
        "## Remediation Roadmap",
        "## Affected Assets",
        "## Findings",
        "## Evidence Appendix",
        "## MITRE ATT&CK Coverage",
    ]

    empty_report = _write_test_report(tmp_path, [])
    populated_report = _write_test_report(
        tmp_path, [_report_finding("Critical Risk", Severity.CRITICAL)]
    )

    for report in (empty_report, populated_report):
        positions = [report.index(section) for section in ordered_sections]
        assert positions == sorted(positions)


def test_report_sorts_findings_by_severity(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path,
        [
            _report_finding("Low Risk", Severity.LOW),
            _report_finding("Critical Risk", Severity.CRITICAL),
        ],
    )

    assert report.index("### Critical Risk") < report.index("### Low Risk")


def test_report_includes_chain_section_when_chains_detected(tmp_path: Path) -> None:
    findings = [
        _report_finding("Discovery", Severity.MEDIUM, "T1046"),
        _report_finding("Kerberoast", Severity.HIGH, "T1558.003"),
        _report_finding("Pass the Hash", Severity.HIGH, "T1550.002"),
        _report_finding("SAM Dump", Severity.CRITICAL, "T1003.002"),
    ]

    report = _write_test_report(tmp_path, findings)

    assert "## Attack Chains Detected" in report
    assert "Full AD Compromise Path" in report


def test_report_includes_affected_assets_table(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("Critical Risk", Severity.CRITICAL)]
    )

    assert "## Affected Assets" in report
    assert "| 10.0.0.1 | 1 |" in report


def test_report_redacts_secrets_with_flag(tmp_path: Path) -> None:
    finding = _report_finding(
        "Credential Exposure",
        Severity.HIGH,
        evidence="alice:Secret123!",
    )
    paths = write_report(
        [finding],
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        redact=True,
    )

    report = paths[0].read_text()

    assert "Secret123!" not in report
    assert "[REDACTED]" in report


def test_report_has_remediation_roadmap_section(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("SMB Signing Disabled", Severity.HIGH)]
    )

    assert "## Remediation Roadmap" in report
    assert "| 1 | SMB Signing Disabled | High | Low |" in report


def test_report_remediation_sorted_by_priority(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path,
        [
            _report_finding("Low Risk", Severity.LOW),
            _report_finding("Critical Risk", Severity.CRITICAL),
        ],
    )

    assert report.index("| 1 | Critical Risk") < report.index("| 2 | Low Risk")


def test_report_remediation_effort_low_for_signing(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("SMB Signing Disabled", Severity.HIGH)]
    )

    assert "| 1 | SMB Signing Disabled | High | Low |" in report


def test_report_shows_fixed_findings_section(tmp_path: Path) -> None:
    old = _report_finding("Anonymous FTP", Severity.MEDIUM)
    paths = write_report(
        [],
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        previous_findings=[old],
    )

    report = paths[0].read_text()
    assert "## Fixed Since Last Engagement" in report
    assert "~~Anonymous FTP~~ (was medium)" in report


def test_report_recommendation_generated_for_smb_relay(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("SMB Relay Possible", Severity.HIGH, "T1557.001")]
    )

    assert "Enable SMB signing and LDAP signing" in report
    assert "Disable LLMNR and NBT-NS" in report


def test_report_recommendation_generated_for_kerberoastable(
    tmp_path: Path,
) -> None:
    report = _write_test_report(
        tmp_path,
        [_report_finding("Kerberoastable Account", Severity.HIGH, "T1558.003")],
    )

    assert "Use strong passwords (25+ chars) for service accounts" in report
    assert "Group Managed Service Accounts" in report


def test_report_html_contains_donut_chart_svg(tmp_path: Path) -> None:
    finding = _report_finding("SMB Relay", Severity.HIGH, "T1557.001")

    path = write_report(
        [finding], tmp_path, engagement_name="Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert '<svg class="donut"' in report
    assert "<path d=" in report


def test_report_html_contains_risk_bars(tmp_path: Path) -> None:
    finding = _report_finding("SMB Relay", Severity.HIGH, "T1557.001")

    path = write_report(
        [finding], tmp_path, engagement_name="Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert "risk-bars" in report
    assert "risk-fill" in report


def test_report_html_has_dark_mode_toggle(tmp_path: Path) -> None:
    path = write_report([], tmp_path, engagement_name="Client", report_format="html")[0]
    report = path.read_text(encoding="utf-8")

    assert "toggleTheme()" in report
    assert "prefers-color-scheme: dark" in report


def test_report_html_finding_cards_collapsible(tmp_path: Path) -> None:
    finding = _report_finding("Critical Risk", Severity.CRITICAL)

    path = write_report(
        [finding], tmp_path, engagement_name="Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert '<details class="finding-card severity-critical">' in report
    assert '<summary class="finding-summary">' in report


def test_report_html_cover_page_has_client_name(tmp_path: Path) -> None:
    path = write_report(
        [], tmp_path, engagement_name="Fallback Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert "Fallback Client" in report
    assert "CONFIDENTIAL" in report


def test_report_html_print_stylesheet_present(tmp_path: Path) -> None:
    path = write_report([], tmp_path, engagement_name="Client", report_format="html")[0]
    report = path.read_text(encoding="utf-8")

    assert "@media print" in report
    assert "print-color-adjust" in report


def test_donut_chart_data_correct_segments() -> None:
    chart = build_donut_chart_data(1, 2, 0, 0, 1)

    assert chart["total"] == 4
    assert [segment["name"] for segment in chart["segments"]] == [
        "critical",
        "high",
        "info",
    ]


def test_donut_chart_handles_zero_findings() -> None:
    chart = build_donut_chart_data(0, 0, 0, 0, 0)

    assert chart["segments"] == []
    assert chart["total"] == 0
    assert chart["empty_color"] == "#94a3b8"


def test_arc_path_valid_svg_syntax() -> None:
    from xml.etree import ElementTree

    path = _arc_path(100, 100, 80, 50, -90, 90)
    ElementTree.fromstring(
        f'<svg xmlns="http://www.w3.org/2000/svg"><path d="{path}"/></svg>'
    )

    assert path.startswith("M ")
    assert path.endswith(" Z")


def test_tactic_bars_built_from_findings() -> None:
    findings = [
        _report_finding("SMB Relay", Severity.HIGH, "T1557.001"),
        _report_finding("Kerberoast", Severity.HIGH, "T1558.003"),
    ]

    bars = build_tactic_bars(findings)

    assert bars
    assert any(bar["count"] >= 1 for bar in bars)


def test_credential_note_has_mitre_tags_plaintext() -> None:
    markdown = _render_credential(secret_type="plaintext")

    assert "tags: [credential, plaintext, T1078, T1110.001]" in markdown


def test_credential_note_has_mitre_tags_ntlm() -> None:
    markdown = _render_credential(secret_type="ntlm")

    assert "tags: [credential, ntlm, T1078, T1550.002]" in markdown


def test_credential_note_severity_plaintext_is_critical() -> None:
    markdown = _render_credential(secret_type="plaintext")

    assert "severity: critical" in markdown


def test_credential_note_severity_ntlm_is_high() -> None:
    markdown = _render_credential(secret_type="ntlm")

    assert "severity: high" in markdown


def test_credential_note_cracked_false_shows_cross() -> None:
    markdown = _render_credential(cracked=False)

    assert "| Cracked | ✗ |" in markdown
    assert "| Cracked Value |" not in markdown


def test_credential_note_cracked_true_shows_tick() -> None:
    markdown = _render_credential(cracked=True, cracked_value="P@ssw0rd")

    assert "| Cracked | ✓ |" in markdown
    assert "| Cracked Value | P@ssw0rd |" in markdown


def test_credential_next_steps_plaintext_contains_evil_winrm() -> None:
    steps = get_credential_next_steps(
        "brandon.stark",
        "iseedeadpeople",
        "plaintext",
        "192.168.56.11",
        "north.sevenkingdoms.local",
    )

    assert any("evil-winrm" in step for step in steps)


def test_credential_next_steps_ntlm_contains_pth() -> None:
    steps = get_credential_next_steps(
        "Administrator",
        "aad3b435...",
        "ntlm",
        "192.168.56.11",
        "CORP",
    )

    assert any("Pass the Hash" in step for step in steps)


def test_credential_next_steps_subnet_derived_correctly() -> None:
    steps = get_credential_next_steps(
        "user",
        "pass",
        "plaintext",
        "192.168.56.11",
        "CORP",
    )

    assert any("192.168.56.0/24" in step for step in steps)


def test_credential_next_steps_invalid_ip_uses_host_as_is() -> None:
    steps = get_credential_next_steps(
        "user",
        "pass",
        "plaintext",
        "not-an-ip",
        "CORP",
    )

    assert any("not-an-ip/24" in step for step in steps)


def test_credential_note_related_finding_link() -> None:
    markdown = _render_credential(related_finding_hash="701365f769")

    assert "## Related Findings" in markdown
    assert "[[701365f769-valid-credential-identified]]" in markdown


def test_write_result_markdown_links_credential_to_source_finding(
    tmp_path: Path,
) -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    note = (tmp_path / "credentials" / "plaintext" / "alice.md").read_text()
    assert "## Related Findings" in note
    assert "- [[" in note
    assert "-valid-credential-identified]]" in note


def test_credential_note_no_related_finding_section_when_none() -> None:
    markdown = _render_credential(related_finding_hash=None)

    assert "## Related Findings" not in markdown


def _write_test_report(tmp_path: Path, findings: list[Finding]) -> str:
    paths = write_report(
        findings,
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        with_defenses=True,
    )
    return paths[0].read_text()


def _report_finding(
    title: str,
    severity: Severity,
    technique_id: str = "T1190",
    evidence: str = "example evidence",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[
            MitreMatch(
                technique_id,
                technique_id,
                "Credential Access",
                1.0,
                "rule",
            )
        ],
        affected_hosts=["10.0.0.1"],
        evidence=evidence,
        next_steps=["Remediate the issue."],
        defenses=[],
        chain_member=None,
        hash=title.casefold().replace(" ", "-"),
    )


def _render_credential(
    *,
    secret_type: str = "plaintext",
    cracked: bool = False,
    cracked_value: str | None = None,
    related_finding_hash: str | None = None,
) -> str:
    return render_credential_markdown(
        Credential(
            username="brandon.stark",
            secret="iseedeadpeople",
            secret_type=secret_type,
            source_host="192.168.56.11",
            domain="north.sevenkingdoms.local",
            cracked=cracked,
            cracked_value=cracked_value,
            related_finding_hash=related_finding_hash,
        ),
        engagement_name="penwinterfellloot",
        tool_name="crackmapexec",
        iso_timestamp="2026-04-27T20:10:23+00:00",
    )

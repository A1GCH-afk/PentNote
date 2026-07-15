from __future__ import annotations

import sys
from pathlib import Path

from lxml import etree
from pentnote.mitre.coverage import coverage_summary
from pentnote.models import Credential, Finding, Host, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser
from pentnote.parsers.c2.generic import GenericC2LogParser
from pentnote.parsers.c2.havoc import HavocLogParser
from pentnote.parsers.c2.registry import detect_c2_parser
from pentnote.parsers.c2.sliver import SliverLogParser
from pentnote.parsers.detector import detect_parser, parser_by_name
from pentnote.parsers.universal import UniversalParser
from pentnote.parsers.v1.crackmapexec import CrackMapExecParser
from pentnote.parsers.v1.impacket import SecretsDumpParser
from pentnote.parsers.v1.nmap import (
    NmapParser,
    _parse_os_from_cpe,
    _parse_os_from_service_info,
)
from pentnote.parsers.v2.certipy import CertipyParser
from pentnote.parsers.v2.enum4linux import Enum4linuxParser
from pentnote.parsers.v2.evilwinrm import EvilWinRMParser
from pentnote.parsers.v2.lazagne import LaZagneParser
from pentnote.parsers.v2.mimikatz import MimikatzParser
from pentnote.parsers.v2.nikto import NiktoParser
from pentnote.parsers.v2.nuclei import NucleiParser
from pentnote.parsers.v2.peas import LinPEASParser, WinPEASParser
from pentnote.parsers.v2.powerview import PowerViewParser
from pentnote.parsers.v2.responder import ResponderParser
from pentnote.parsers.v2.rubeus import RubeusParser
from pentnote.parsers.v2.seatbelt import SeatbeltParser
from pentnote.parsers.v2.smbclient import SmbClientParser
from pentnote.parsers.v2.sqlmap import SQLMapParser
from pentnote.parsers.v15.bloodhound import BloodHoundParser
from pentnote.parsers.v15.feroxbuster import FeroxbusterParser
from pentnote.parsers.v15.gobuster import GobusterParser
from pentnote.parsers.v15.kerbrute import KerbruteParser
from pentnote.parsers.v15.ldapdomaindump import LDAPDomainDumpParser

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_EXAMPLE = PROJECT_ROOT / "examples" / "plugin_example"
if str(PLUGIN_EXAMPLE) not in sys.path:
    sys.path.insert(0, str(PLUGIN_EXAMPLE))

from myparser.parser import MyScannerParser  # noqa: E402

RUBEUS_KERBEROAST = (FIXTURES / "rubeus_kerberoast.txt").read_text()
RUBEUS_ASREPROAST = (FIXTURES / "rubeus_asreproast.txt").read_text()
MIMIKATZ_OUTPUT = (FIXTURES / "mimikatz_logonpasswords.txt").read_text()
ENUM4LINUX_OUTPUT = (FIXTURES / "enum4linux_full.txt").read_text()
CERTIPY_OUTPUT = (FIXTURES / "certipy_find.txt").read_text()
WINPEAS_OUTPUT = (FIXTURES / "winpeas_sample.txt").read_text()
LINPEAS_OUTPUT = (FIXTURES / "linpeas_sample.txt").read_text()
RESPONDER_OUTPUT = (FIXTURES / "responder_sample.log").read_text()
POWERVIEW_OUTPUT = (FIXTURES / "powerview_sample.txt").read_text()
SEATBELT_OUTPUT = (FIXTURES / "seatbelt_sample.txt").read_text()
LAZAGNE_OUTPUT = (FIXTURES / "lazagne_sample.txt").read_text()
SMBCLIENT_SHARES = (FIXTURES / "smbclient_shares.txt").read_text()
SMBCLIENT_DIR = (FIXTURES / "smbclient_dir.txt").read_text()


def _nmap_host(xml: str):
    return etree.fromstring(xml).find(".//host")


def test_nmap_can_parse_correct_tool_output() -> None:
    content = (FIXTURES / "nmap_sample.xml").read_text()

    assert NmapParser().can_parse(content) > 0.9


def test_nmap_can_parse_wrong_tool_output_low_confidence() -> None:
    content = "SMB 192.168.56.10 445 HOST [+] LAB\\user:Password123!"

    assert NmapParser().can_parse(content) < 0.1


def test_nmap_parse_returns_host_objects() -> None:
    content = (FIXTURES / "nmap_sample.xml").read_text()

    result = NmapParser().parse(content)

    assert result.partial is False
    assert isinstance(result.hosts[0], Host)
    assert result.hosts[0].ip == "10.129.48.183"
    assert result.hosts[0].ports[0].service == "ssh"


def test_nmap_parse_returns_host_objects_from_normal_text() -> None:
    content = """Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for target.htb (10.129.48.183)
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 20.12 seconds
"""

    parser = NmapParser()
    result = parser.parse(content)

    assert parser.can_parse(content) > 0.9
    assert result.hosts[0].ip == "10.129.48.183"
    assert result.hosts[0].hostname == "target.htb"
    assert result.hosts[0].os == "Linux"
    assert result.hosts[0].ports[0].service == "ssh"
    assert result.hosts[0].ports[0].version == "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10"


def test_nmap_parse_handles_truncated_partial_input() -> None:
    content = (FIXTURES / "nmap_sample.xml").read_text()[:-20]

    result = NmapParser().parse(content)

    assert result.partial is True
    assert result.hosts[0].ip == "10.129.48.183"


def test_nmap_handles_empty_input() -> None:
    result = NmapParser().safe_parse("")

    assert result.tool == "nmap"
    assert result.partial is False
    assert result.hosts == []
    assert result.findings == []


def test_nmap_handles_ansi_codes() -> None:
    content = "\x1b[31m" + (FIXTURES / "nmap_sample.xml").read_text() + "\x1b[0m"

    result = NmapParser().safe_parse(content)

    assert result.hosts[0].ip == "10.129.48.183"


def test_nmap_handles_truncated_xml() -> None:
    content = (FIXTURES / "nmap_sample.xml").read_text()[:-20]

    result = NmapParser().safe_parse(content)

    assert result.partial is True
    assert result.hosts[0].ip == "10.129.48.183"


def test_nmap_does_not_truncate_long_script_lines() -> None:
    """A long <script> elem line (e.g. a base64 cert) must not be truncated.

    Truncating it mid-tag corrupts the XML from that byte on; lxml's
    recover=True then cascades tag-mismatch errors through the rest of the
    document, silently dropping every port that comes after it.
    """

    content = (FIXTURES / "nmap_long_script_line.xml").read_text()

    result = NmapParser().safe_parse(content)

    assert result.partial is False
    assert result.hosts[0].ports[0].number != 0
    port_numbers = sorted(port.number for port in result.hosts[0].ports)
    assert port_numbers == [53, 389, 445, 3268]


def test_nmap_low_confidence_port_mid_list_does_not_drop_later_ports() -> None:
    """A low-confidence, unversioned <service> (conf=3, method=table) in the
    middle of the port list must not prevent later ports from parsing."""

    content = (FIXTURES / "nmap_long_script_line.xml").read_text()

    result = NmapParser().parse(content)

    port_445 = next(p for p in result.hosts[0].ports if p.number == 445)
    assert port_445.service == "microsoft-ds"
    assert port_445.version is None
    port_3268 = next(p for p in result.hosts[0].ports if p.number == 3268)
    assert port_3268.service == "ldap"


def test_os_from_osmatch() -> None:
    host = _nmap_host("""
        <nmaprun>
          <host>
            <address addr="10.10.10.10" addrtype="ipv4"/>
            <os><osmatch name="Linux 5.4" accuracy="97"/></os>
          </host>
        </nmaprun>
        """)

    assert NmapParser()._extract_os(host) == "Linux 5.4"


def test_nmap_parse_os_from_service_cpe() -> None:
    content = """
    <nmaprun scanner="nmap">
      <host>
        <address addr="10.129.48.196" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" cpe="cpe:/o:linux:linux_kernel"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    result = NmapParser().parse(content)

    assert result.hosts[0].os == "Linux"


def test_nmap_parse_os_from_service_cpe_child() -> None:
    content = """
    <nmaprun scanner="nmap">
      <host>
        <address addr="192.168.56.11" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="88">
            <state state="open"/>
            <service name="kerberos-sec">
              <cpe>cpe:/o:microsoft:windows</cpe>
            </service>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    result = NmapParser().parse(content)

    assert result.hosts[0].os == "Windows"


def test_nmap_parse_os_from_service_info_script() -> None:
    content = """
    <nmaprun scanner="nmap">
      <host>
        <address addr="10.129.48.196" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh"/>
            <script id="banner" output="Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    result = NmapParser().parse(content)

    assert result.hosts[0].os == "Linux"


def test_os_from_cpe_linux() -> None:
    assert _parse_os_from_cpe("cpe:/o:linux:linux_kernel") == "Linux"


def test_os_from_cpe_windows() -> None:
    assert _parse_os_from_cpe("cpe:/o:microsoft:windows") == "Windows"


def test_os_from_cpe_macos() -> None:
    assert _parse_os_from_cpe("cpe:/o:apple:mac_os_x") == "macOS"


def test_os_from_cpe_application_returns_none() -> None:
    assert _parse_os_from_cpe("cpe:/a:openbsd:openssh") is None


def test_os_from_cpe_empty_returns_none() -> None:
    assert _parse_os_from_cpe("") is None


def test_os_from_service_info_linux() -> None:
    output = (
        "Service Info: Host: localhost; OS: Linux; " "CPE: cpe:/o:linux:linux_kernel"
    )

    assert _parse_os_from_service_info(output) == "Linux"


def test_os_from_service_info_windows() -> None:
    output = "Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows"

    assert _parse_os_from_service_info(output) == "Windows"


def test_os_from_service_info_missing_returns_none() -> None:
    assert _parse_os_from_service_info("just some script output") is None


def test_os_priority_osmatch_wins() -> None:
    host = _nmap_host("""
        <nmaprun>
          <host>
            <address addr="10.10.10.10" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <service name="ssh" cpe="cpe:/o:linux:linux_kernel"/>
              </port>
            </ports>
            <os><osmatch name="Linux 5.4" accuracy="97"/></os>
          </host>
        </nmaprun>
        """)

    assert NmapParser()._extract_os(host) == "Linux 5.4"


def test_os_graceful_fallback() -> None:
    host = _nmap_host("""
        <nmaprun>
          <host>
            <address addr="10.10.10.10" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <service name="ssh" cpe="cpe:/a:openbsd:openssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """)

    assert NmapParser()._extract_os(host) is None


def test_cme_parser_contract_and_partial_recovery() -> None:
    content = (FIXTURES / "cme_sample.txt").read_text()
    parser = CrackMapExecParser()

    result = parser.parse(f"{content}\nnot a complete cme line")

    assert parser.can_parse(content) > 0.9
    assert parser.can_parse((FIXTURES / "nmap_sample.xml").read_text()) < 0.1
    assert result.partial is True
    assert isinstance(result.hosts[0], Host)
    assert isinstance(result.credentials[0], Credential)
    assert all(isinstance(item, Finding) for item in result.findings)
    assert [item.hash for item in parser.parse(content).findings] == [
        item.hash for item in parser.parse(content).findings
    ]


def test_cme_enum_av_extracts_defender() -> None:
    result = CrackMapExecParser().parse(
        "SMB  10.10.10.10  445  DC01  [*] Windows Defender (enabled)"
    )

    assert result.hosts[0].av_products == ["Windows Defender"]


def test_cme_enum_av_extracts_crowdstrike() -> None:
    result = CrackMapExecParser().parse(
        "SMB  10.10.10.10  445  DC01  [*] CrowdStrike Falcon (enabled)"
    )

    assert result.hosts[0].av_products == ["CrowdStrike Falcon"]


def test_cme_enum_av_tags_host_with_av_active() -> None:
    result = CrackMapExecParser().parse(
        "SMB  10.10.10.10  445  DC01  [*] Windows Defender (enabled)"
    )

    assert "av:windows-defender" in result.hosts[0].tags
    assert "av-active" in result.hosts[0].tags


def test_cme_handles_empty_input() -> None:
    result = CrackMapExecParser().safe_parse("")

    assert result.tool == "crackmapexec"
    assert result.findings == []


def test_cme_handles_binary_garbage() -> None:
    result = CrackMapExecParser().safe_parse("\x00\x00\x1b[31m\xff\xfe\x00")

    assert result.tool == "crackmapexec"
    assert isinstance(result.findings, list)


def test_cme_saved_to_artifact_line_becomes_loot_instead_of_being_dropped() -> None:
    """An nxc '... saved to: <path>' line must be recorded as loot, not dropped.

    Root cause: these lines parse cleanly under the CME line grammar but were
    neither a credential, a finding, nor a host field, so the generated
    artifact path (here a --generate-krb5-file output) fell through every
    branch and was silently discarded. The trailing "export KRB5_CONFIG"
    guidance line is benign follow-up, so the parse stays non-partial with
    zero findings — the only new record is the loot entry.
    """

    content = (FIXTURES / "cme_krb5_artifact.txt").read_text()

    result = CrackMapExecParser().parse(content)

    assert len(result.loot) == 1
    loot = result.loot[0]
    assert loot.type == "file"
    assert loot.path == "./krb5.conf"
    assert loot.host == "10.10.11.174"
    assert "krb5" in loot.notes.casefold()
    # No credential was tested, so findings stays 0 and the parse is complete.
    assert result.findings == []
    assert result.partial is False


def test_cme_credential_validation_unchanged_by_artifact_handling() -> None:
    """The credential path must keep working after artifact/loot handling was added."""

    result = CrackMapExecParser().parse(
        "SMB  192.168.56.10  445  DC01  [+] LAB\\alice:Password123! (Pwn3d!)"
    )

    assert len(result.credentials) == 1
    assert result.credentials[0].username == "alice"
    assert [f.title for f in result.findings] == ["Administrative access confirmed"]
    assert result.loot == []


def test_cme_uncategorized_success_line_is_surfaced_not_silently_dropped() -> None:
    """A '[+]' success line we can't classify must leave a visible trace.

    Previously any grammar-matched line that produced no record inflated the
    parsed count, so the parse looked complete (partial=False) even though
    actionable output was thrown away. Such lines now mark the parse partial
    and are collected into a single INFO finding naming the exact lines.
    """

    result = CrackMapExecParser().parse(
        "SMB  10.10.10.5  445  DC01  [+] Enumerated 3 shares with WRITE access"
    )

    assert result.partial is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "Unrecognized crackmapexec output"
    assert finding.severity is Severity.INFO
    assert "WRITE access" in finding.evidence


def test_secretsdump_parser_contract_and_partial_recovery() -> None:
    content = (FIXTURES / "impacket_sample.txt").read_text()
    parser = SecretsDumpParser()

    result = parser.parse(content.replace("Guest:501:aad3", "Guest:501:aad3-bad"))

    assert parser.can_parse(content) > 0.9
    assert parser.can_parse((FIXTURES / "nmap_sample.xml").read_text()) < 0.1
    assert result.partial is True
    assert isinstance(result.credentials[0], Credential)
    assert all(isinstance(item, Finding) for item in result.findings)
    assert [item.hash for item in parser.parse(content).findings] == [
        item.hash for item in parser.parse(content).findings
    ]


def test_universal_parser_extracts_six_indicator_types() -> None:
    content = (
        "host 192.168.56.20 has 8080/tcp open, CVE-2024-12345, "
        "user: alice, https://example.test/login and hash "
        "31d6cfe0d16ae931b73c59d7e0c089c0"
    )

    result = UniversalParser().parse(content)
    title_prefixes = {finding.title.split(":", 1)[0] for finding in result.findings}

    assert {
        "IPv4 address observed",
        "Port reference observed",
        "Hash material observed",
        "CVE reference observed",
        "Username observed",
        "URL observed",
    } <= title_prefixes


def test_universal_no_finding_under_threshold() -> None:
    result = UniversalParser().parse("Review CVE-2024-12345 on 10.10.10.10")

    assert result.findings == []


def test_universal_hash_extraction_does_not_split_sha256() -> None:
    # Regression: a single 64-char SHA-256 must be captured whole, not chopped
    # into two 32-char halves (bloodyAD "sha256 of RSA key" + trailing NT hash).
    from pentnote.parsers.universal import _HASH, _scan

    content = (
        "sha256 of RSA key: "
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "NT: ffeeddccbbaa99887766554433221100"
    )

    assert _scan(_HASH, content) == [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ffeeddccbbaa99887766554433221100",
    ]


def test_universal_ignores_non_digest_length_hex_run() -> None:
    # An over-length hex blob (65 chars) is not a recognised digest and must not
    # yield a spurious 32/40/64-char sub-match at an offset.
    from pentnote.parsers.universal import _HASH, _scan

    assert _scan(_HASH, "blob " + "a" * 65 + " end") == []


def test_safe_parse_never_raises() -> None:
    class BrokenParser(AbstractParser):
        tool_name = "broken"

        def can_parse(self, content: str) -> float:
            return 1.0

        def parse(self, content: str) -> ParsedResult:
            raise RuntimeError("boom")

    result = BrokenParser().safe_parse("anything")

    assert result.partial is True
    assert result.findings[0].title == "Parser error: broken"


def test_score_parsers_surfaces_detection_errors(monkeypatch, capsys) -> None:
    """A parser raising in can_parse must warn, not silently score 0.

    Regression guard: the detector used to swallow can_parse exceptions, making
    a broken parser indistinguishable from one that simply does not match.
    """

    from pentnote.parsers import detector

    class DetectionBoomParser(AbstractParser):
        tool_name = "detection-boom"

        def can_parse(self, content: str) -> float:
            raise ValueError("kaboom")

        def parse(self, content: str) -> ParsedResult:
            raise NotImplementedError

    monkeypatch.setattr(
        detector,
        "available_parsers",
        lambda include_plugins=True: [DetectionBoomParser()],
    )

    scores = detector.score_parsers("some tool output")
    captured = capsys.readouterr()

    assert scores[0].score == 0.0  # broken parser cannot win detection
    assert "detection-boom" in captured.err  # but the failure is surfaced
    assert "kaboom" in captured.err


def test_clean_removes_ansi_codes() -> None:
    cleaned = UniversalParser().clean("\x1b[31mRed text\x1b[0m\nNormal")

    assert "\x1b" not in cleaned
    assert cleaned == "Red text\nNormal"


def test_clean_truncates_long_lines() -> None:
    cleaned = UniversalParser().clean("A" * 3000)

    assert len(cleaned) < 2050
    assert cleaned.endswith("[truncated]")


def test_powerview_can_parse() -> None:
    assert PowerViewParser().can_parse(POWERVIEW_OUTPUT) > 0.85


def test_powerview_extracts_domain_users() -> None:
    result = PowerViewParser().parse(POWERVIEW_OUTPUT)

    users = [obj for obj in result.domain_objects if obj.object_type == "user"]
    assert any(obj.name == "robb.stark" for obj in users)
    assert any(obj.name == "brandon.stark" for obj in users)


def test_powerview_local_admin_access_is_critical() -> None:
    result = PowerViewParser().parse(POWERVIEW_OUTPUT)

    finding = next(
        item for item in result.findings if "Local Admin Access" in item.title
    )
    assert finding.severity == Severity.CRITICAL


def test_powerview_kerberoastable_maps_t1558_003() -> None:
    result = PowerViewParser().parse(POWERVIEW_OUTPUT)

    finding = next(item for item in result.findings if "Kerberoastable" in item.title)
    assert finding.mitre_matches[0].technique_id == "T1558.003"


def test_powerview_unconstrained_delegation_critical() -> None:
    result = PowerViewParser().parse(POWERVIEW_OUTPUT)

    finding = next(
        item for item in result.findings if "Unconstrained Delegation" in item.title
    )
    assert finding.severity == Severity.CRITICAL


def test_seatbelt_can_parse() -> None:
    assert SeatbeltParser().can_parse(SEATBELT_OUTPUT) > 0.85


def test_seatbelt_defender_disabled_is_high() -> None:
    result = SeatbeltParser().parse(SEATBELT_OUTPUT)

    finding = next(item for item in result.findings if "Defender" in item.title)
    assert finding.severity == Severity.HIGH


def test_seatbelt_uac_disabled_is_high() -> None:
    result = SeatbeltParser().parse(SEATBELT_OUTPUT)

    finding = next(item for item in result.findings if "UAC" in item.title)
    assert finding.severity == Severity.HIGH


def test_seatbelt_autologon_creds_is_critical() -> None:
    result = SeatbeltParser().parse(SEATBELT_OUTPUT)

    finding = next(item for item in result.findings if "AutoLogon" in item.title)
    assert finding.severity == Severity.CRITICAL
    assert result.credentials[0].secret_type == "plaintext"


def test_seatbelt_laps_missing_is_medium() -> None:
    result = SeatbeltParser().parse(SEATBELT_OUTPUT)

    finding = next(item for item in result.findings if "LAPS" in item.title)
    assert finding.severity == Severity.MEDIUM


def test_lazagne_can_parse() -> None:
    assert LaZagneParser().can_parse(LAZAGNE_OUTPUT) > 0.85


def test_lazagne_extracts_browser_credentials() -> None:
    result = LaZagneParser().parse(LAZAGNE_OUTPUT)

    assert any(cred.username == "robb.stark" for cred in result.credentials)
    assert any(
        "browser-cred" in " ".join(finding.next_steps) for finding in result.findings
    )


def test_lazagne_credential_type_is_plaintext() -> None:
    result = LaZagneParser().parse(LAZAGNE_OUTPUT)

    firefox = next(cred for cred in result.credentials if cred.username == "robb.stark")
    assert firefox.secret_type == "plaintext"


def test_lazagne_multiple_apps_summary_finding() -> None:
    result = LaZagneParser().parse(LAZAGNE_OUTPUT)

    assert any(
        "Multiple Credential Stores Compromised" in finding.title
        for finding in result.findings
    )


def test_lazagne_maps_t1555() -> None:
    result = LaZagneParser().parse(LAZAGNE_OUTPUT)

    assert any(
        match.technique_id == "T1555"
        for finding in result.findings
        for match in finding.mitre_matches
    )


def test_evilwinrm_can_parse_transcript() -> None:
    content = (FIXTURES / "evilwinrm_sample.txt").read_text()

    assert EvilWinRMParser().can_parse(content) > 0.9


def test_evilwinrm_detected_before_universal() -> None:
    result = detect_parser((FIXTURES / "evilwinrm_sample.txt").read_text())

    assert result.parser.tool_name == "evil-winrm"


def test_evilwinrm_extracts_high_value_findings() -> None:
    result = EvilWinRMParser().parse((FIXTURES / "evilwinrm_sample.txt").read_text())
    titles = {finding.title for finding in result.findings}

    assert "WinRM Session Has Local Administrator Rights" in titles
    assert "Dangerous Windows Privileges Enabled (4)" in titles
    assert "Domain Users Enumerated (16)" in titles
    assert "Domain Groups Enumerated (3)" in titles
    assert "Domain User Details Enumerated: arya.stark" in titles


def test_evilwinrm_creates_domain_objects() -> None:
    result = EvilWinRMParser().parse((FIXTURES / "evilwinrm_sample.txt").read_text())
    objects = {(obj.object_type, obj.name) for obj in result.domain_objects}

    assert ("user", "robb.stark") in objects
    assert ("user", "arya.stark") in objects
    assert ("group", "Domain Admins") in objects


def _domain_object(result: ParsedResult, object_type: str, name: str) -> object:
    for obj in result.domain_objects:
        if obj.object_type == object_type and obj.name.casefold() == name.casefold():
            return obj
    raise AssertionError(f"no {object_type} object named {name!r}")


def test_evilwinrm_net_user_populates_user_note_properties() -> None:
    content = (FIXTURES / "evilwinrm_netuser_netgroup.txt").read_text()

    result = EvilWinRMParser().parse(content)
    admin = _domain_object(result, "user", "Administrator")

    assert admin.properties["Account active"] == "Yes"
    assert admin.properties["Password last set"] == "4/16/2026 7:41:53 AM"
    assert admin.properties["Local Group Memberships"] == ["Administrators"]
    # '*'-prefixed memberships, including the wrapped continuation lines.
    assert "Domain Admins" in admin.properties["Global Group memberships"]
    assert "Enterprise Admins" in admin.properties["Global Group memberships"]


def test_evilwinrm_net_group_populates_group_note_members() -> None:
    content = (FIXTURES / "evilwinrm_netuser_netgroup.txt").read_text()

    result = EvilWinRMParser().parse(content)
    group = _domain_object(result, "group", "Domain Admins")

    assert group.properties["Comment"] == "Designated administrators of the domain"
    assert group.properties["Members"] == ["Administrator", "svc_recovery"]


def test_evilwinrm_net_user_note_survives_whoami_sid_header() -> None:
    # The whoami /all "User Name  SID" header must not be parsed as a net user.
    content = (FIXTURES / "evilwinrm_sample.txt").read_text()

    result = EvilWinRMParser().parse(content)
    user_names = {obj.name.casefold() for obj in result.domain_objects}

    assert "sid" not in user_names
    arya = _domain_object(result, "user", "arya.stark")
    assert arya.properties["Account active"] == "Yes"
    assert arya.properties["Global Group memberships"] == ["Domain Users", "Stark"]


def test_detector_picks_highest_confidence_parser() -> None:
    assert (
        detect_parser((FIXTURES / "nmap_sample.xml").read_text()).parser.tool_name
        == "nmap"
    )
    assert (
        detect_parser((FIXTURES / "cme_sample.txt").read_text()).parser.tool_name
        == "crackmapexec"
    )
    assert (
        detect_parser((FIXTURES / "impacket_sample.txt").read_text()).parser.tool_name
        == "impacket-secretsdump"
    )
    assert (
        detect_parser(
            (FIXTURES / "bloodhound_sample.json").read_text()
        ).parser.tool_name
        == "bloodhound"
    )
    assert (
        detect_parser((FIXTURES / "kerbrute_sample.txt").read_text()).parser.tool_name
        == "kerbrute"
    )
    assert (
        detect_parser(
            (FIXTURES / "ldapdomaindump_sample.json").read_text()
        ).parser.tool_name
        == "ldapdomaindump"
    )
    assert (
        detect_parser((FIXTURES / "gobuster_sample.txt").read_text()).parser.tool_name
        == "gobuster"
    )
    assert (
        detect_parser(
            (FIXTURES / "feroxbuster_sample.txt").read_text()
        ).parser.tool_name
        == "feroxbuster"
    )
    assert (
        detect_parser((FIXTURES / "nikto_sample.txt").read_text()).parser.tool_name
        == "nikto"
    )
    assert (
        detect_parser((FIXTURES / "nuclei_sample.txt").read_text()).parser.tool_name
        == "nuclei"
    )
    assert (
        detect_parser((FIXTURES / "certipy_find.txt").read_text()).parser.tool_name
        == "certipy"
    )
    assert (
        detect_parser(
            "sqlmap identified that parameter id is injectable"
        ).parser.tool_name
        == "sqlmap"
    )
    assert detect_parser("Review CVE-2024-12345").parser.tool_name == "universal"


def test_plugin_example_can_parse_sample() -> None:
    sample = """[MyScanner] Scan complete
HOST 10.10.10.10 web01 Linux
CRED alice:Password123!@10.10.10.10
VULN 10.10.10.10 Public exploit found
"""

    assert MyScannerParser().can_parse(sample) == 1.0


def test_plugin_example_returns_parsed_result() -> None:
    sample = """[MyScanner] Scan complete
HOST 10.10.10.10 web01 Linux
CRED alice:Password123!@10.10.10.10
VULN 10.10.10.10 Public exploit found
"""

    result = MyScannerParser().parse(sample)

    assert isinstance(result, ParsedResult)
    assert result.tool == "myscanner"
    assert result.hosts[0].ip == "10.10.10.10"
    assert result.credentials[0].username == "alice"
    assert result.findings[0].mitre_matches[0].technique_id == "T1190"


def test_phase_four_parsers_return_object_types_and_partial_results() -> None:
    cases = [
        (BloodHoundParser(), "bloodhound_sample.json", "domain_objects"),
        (KerbruteParser(), "kerbrute_sample.txt", "credentials"),
        (LDAPDomainDumpParser(), "ldapdomaindump_sample.json", "domain_objects"),
        (GobusterParser(), "gobuster_sample.txt", "findings"),
        (FeroxbusterParser(), "feroxbuster_sample.txt", "findings"),
        (NiktoParser(), "nikto_sample.txt", "findings"),
        (NucleiParser(), "nuclei_sample.txt", "findings"),
    ]

    for parser, fixture, attribute in cases:
        content = (FIXTURES / fixture).read_text()
        result = parser.parse(content)

        assert parser.can_parse(content) > 0.9
        assert getattr(result, attribute)


def test_phase_four_finding_hashes_are_idempotent() -> None:
    for parser, fixture in [
        (KerbruteParser(), "kerbrute_sample.txt"),
        (GobusterParser(), "gobuster_sample.txt"),
        (FeroxbusterParser(), "feroxbuster_sample.txt"),
        (NiktoParser(), "nikto_sample.txt"),
        (NucleiParser(), "nuclei_sample.txt"),
        (SQLMapParser(), "sqlmap_sample.txt"),
    ]:
        content = (FIXTURES / fixture).read_text()

        assert [item.hash for item in parser.parse(content).findings] == [
            item.hash for item in parser.parse(content).findings
        ]


def test_gobuster_parses_vhost_output() -> None:
    content = """===============================================================
Gobuster v3.8.2
===============================================================
[+] Url:                       http://silentium.htb
Starting gobuster in VHOST enumeration mode
===============================================================
staging.silentium.htb Status: 200 [Size: 3142]
===============================================================
Finished
===============================================================
"""

    result = GobusterParser().parse(content)

    assert result.findings
    assert result.findings[0].title == (
        "Web virtual host discovered: staging.silentium.htb"
    )
    assert result.findings[0].severity == Severity.LOW


def test_gobuster_vhost_confidence() -> None:
    content = """Gobuster v3.8.2
staging.silentium.htb Status: 200 [Size: 3142]
"""

    assert GobusterParser().can_parse(content) > 0.6


def test_gobuster_handles_long_lines() -> None:
    content = "Gobuster v3.8.2\n" + ("A" * 5000)

    result = GobusterParser().safe_parse(content)

    assert result.tool == "gobuster"
    assert "truncated" in result.raw_text or result.findings == []


def test_rubeus_can_parse_kerberoast() -> None:
    assert RubeusParser().can_parse(RUBEUS_KERBEROAST) > 0.9


def test_rubeus_extracts_username() -> None:
    result = RubeusParser().parse(RUBEUS_KERBEROAST)

    assert result.credentials[0].username == "svc_backup"


def test_rubeus_credential_type_is_kerberos() -> None:
    result = RubeusParser().parse(RUBEUS_KERBEROAST)

    assert result.credentials[0].secret_type == "kerberos"


def test_rubeus_finding_mitre_t1558_003() -> None:
    result = RubeusParser().parse(RUBEUS_KERBEROAST)
    ttps = [m.technique_id for f in result.findings for m in f.mitre_matches]

    assert "T1558.003" in ttps


def test_rubeus_asreproast_mitre_t1558_004() -> None:
    result = RubeusParser().parse(RUBEUS_ASREPROAST)
    ttps = [m.technique_id for f in result.findings for m in f.mitre_matches]

    assert "T1558.004" in ttps


def test_certipy_can_parse_find_output() -> None:
    assert CertipyParser().can_parse(CERTIPY_OUTPUT) > 0.9


def test_certipy_extracts_adcs_vulnerability_finding() -> None:
    result = CertipyParser().parse(CERTIPY_OUTPUT)

    assert result.findings[0].title == "AD CS ESC13 on Template TemporaryWinRM"
    assert result.findings[0].affected_hosts == ["dc1.ping.htb"]
    assert result.findings[0].severity == Severity.HIGH


def test_certipy_extracts_ca_and_template_objects() -> None:
    result = CertipyParser().parse(CERTIPY_OUTPUT)
    object_names = {item.name for item in result.domain_objects}

    assert {"ping-DC1-CA", "TemporaryWinRM"} <= object_names
    assert any(
        item.object_type == "certificate_template" for item in result.domain_objects
    )


def test_mimikatz_can_parse() -> None:
    assert MimikatzParser().can_parse(MIMIKATZ_OUTPUT) > 0.9


def test_mimikatz_extracts_ntlm() -> None:
    result = MimikatzParser().parse(MIMIKATZ_OUTPUT)
    creds = [c for c in result.credentials if c.secret_type == "ntlm"]

    assert len(creds) > 0
    assert creds[0].username == "Administrator"


def test_mimikatz_extracts_plaintext() -> None:
    result = MimikatzParser().parse(MIMIKATZ_OUTPUT)
    creds = [c for c in result.credentials if c.secret_type == "plaintext"]

    assert len(creds) > 0
    assert creds[0].secret == "P@ssw0rd123"


def test_mimikatz_skips_null_passwords() -> None:
    result = MimikatzParser().parse(MIMIKATZ_OUTPUT)

    assert all(c.secret != "(null)" for c in result.credentials)
    assert all(c.username != "Guest" for c in result.credentials)


def test_mimikatz_finding_mitre_t1003_001() -> None:
    result = MimikatzParser().parse(MIMIKATZ_OUTPUT)
    ttps = [m.technique_id for f in result.findings for m in f.mitre_matches]

    assert "T1003.001" in ttps


def test_enum4linux_can_parse() -> None:
    assert Enum4linuxParser().can_parse(ENUM4LINUX_OUTPUT) > 0.9


def test_enum4linux_extracts_users() -> None:
    result = Enum4linuxParser().parse(ENUM4LINUX_OUTPUT)
    users = [d for d in result.domain_objects if d.object_type == "user"]

    assert any(user.name == "Administrator" for user in users)


def test_enum4linux_extracts_shares() -> None:
    result = Enum4linuxParser().parse(ENUM4LINUX_OUTPUT)
    shares = [d for d in result.domain_objects if d.object_type == "share"]

    assert len(shares) > 0


def test_enum4linux_anonymous_smb_finding() -> None:
    result = Enum4linuxParser().parse(ENUM4LINUX_OUTPUT)
    titles = [f.title for f in result.findings]

    assert any("Anonymous SMB" in title for title in titles)


def test_enum4linux_null_session_mitre_t1069() -> None:
    result = Enum4linuxParser().parse(ENUM4LINUX_OUTPUT)
    ttps = [m.technique_id for f in result.findings for m in f.mitre_matches]

    assert "T1069.002" in ttps


def test_smbclient_can_parse_share_listing() -> None:
    assert SmbClientParser().can_parse(SMBCLIENT_SHARES) > 0.9


def test_smbclient_detected_before_universal() -> None:
    assert detect_parser(SMBCLIENT_SHARES).parser.tool_name == "smbclient"
    assert detect_parser(SMBCLIENT_DIR).parser.tool_name == "smbclient"


def test_smbclient_no_false_positive_on_crackmapexec() -> None:
    assert SmbClientParser().can_parse((FIXTURES / "cme_sample.txt").read_text()) == 0.0


def test_smbclient_extracts_shares_and_flags_non_default() -> None:
    result = SmbClientParser().parse(SMBCLIENT_SHARES)
    shares = {obj.name: obj.properties for obj in result.domain_objects}

    assert shares["ADMIN$"]["default"] is True
    assert shares["IPC$"]["type"] == "IPC"
    assert shares["Reports"]["default"] is False
    assert shares["Reports"]["comment"] == "Weekly report drop"


def test_smbclient_share_enumeration_finding_t1135() -> None:
    result = SmbClientParser().parse(SMBCLIENT_SHARES)
    finding = next(f for f in result.findings if f.title.startswith("SMB Shares"))

    assert finding.severity is Severity.LOW
    assert "T1135" in {m.technique_id for m in finding.mitre_matches}
    # The non-default shares are surfaced for follow-up, not the admin shares.
    assert "Logs" in finding.next_steps[0]
    assert "Reports" in finding.next_steps[0]
    assert "ADMIN$" not in finding.next_steps[0]
    assert result.hosts[0].ip == "10.10.11.174"


def test_smbclient_strips_terminal_noise_and_extracts_files() -> None:
    # The interactive capture carries bracketed-paste `\x1b[?2004h` noise the
    # base cleaner leaves behind; the parser must strip it and still list files.
    assert "\x1b" in SMBCLIENT_DIR  # fixture really does carry the escape bytes

    result = SmbClientParser().parse(SMBCLIENT_DIR)
    finding = next(f for f in result.findings if "Contents" in f.title)

    assert "Reports" in finding.title
    assert "T1039" in {m.technique_id for m in finding.mitre_matches}
    assert "\x1b" not in finding.evidence
    assert "Q1_Report.log" in finding.evidence
    # `.` and `..` directory entries are not counted as files.
    assert "(3 file(s))" in finding.title


def test_responder_can_parse_ntlmv2_output() -> None:
    assert ResponderParser().can_parse(RESPONDER_OUTPUT) > 0.85


def test_responder_cannot_parse_nmap() -> None:
    assert (
        ResponderParser().can_parse((FIXTURES / "nmap_sample.xml").read_text()) == 0.0
    )


def test_responder_extracts_username_and_domain() -> None:
    result = ResponderParser().parse(RESPONDER_OUTPUT)

    assert result.credentials[0].username == "brandon.stark"
    assert result.credentials[0].domain == "NORTH"


def test_responder_secret_type_is_net_ntlmv2() -> None:
    result = ResponderParser().parse(RESPONDER_OUTPUT)

    assert result.credentials[0].secret_type == "net-ntlmv2"


def test_responder_finding_maps_t1557_001() -> None:
    result = ResponderParser().parse(RESPONDER_OUTPUT)
    ttps = [
        match.technique_id
        for finding in result.findings
        for match in finding.mitre_matches
    ]

    assert "T1557.001" in ttps


def test_responder_multiple_hashes_generates_summary_finding() -> None:
    content = "\n".join(
        [
            RESPONDER_OUTPUT,
            "[SMB] NTLMv2-SSP Hash     : arya::NORTH:def456:HASH_2",
            "[SMB] NTLMv2-SSP Hash     : sansa::NORTH:ghi789:HASH_3",
            "[SMB] NTLMv2-SSP Hash     : robb::NORTH:jkl012:HASH_4",
        ]
    )
    result = ResponderParser().parse(content)

    assert any(f.title == "Multiple NTLM Hashes Captured (4)" for f in result.findings)


def test_responder_next_steps_include_hashcat_mode_5600() -> None:
    result = ResponderParser().parse(RESPONDER_OUTPUT)

    assert "hashcat -m 5600 hash.txt rockyou.txt" in result.findings[0].next_steps


def test_winpeas_can_parse() -> None:
    assert WinPEASParser().can_parse(WINPEAS_OUTPUT) > 0.85


def test_winpeas_cannot_parse_nmap() -> None:
    assert WinPEASParser().can_parse((FIXTURES / "nmap_sample.xml").read_text()) == 0.0


def test_winpeas_extracts_unquoted_service_path() -> None:
    titles = [
        finding.title for finding in WinPEASParser().parse(WINPEAS_OUTPUT).findings
    ]

    assert "Unquoted Service Path: VulnSvc" in titles


def test_winpeas_extracts_alwaysinstallelevated() -> None:
    titles = [
        finding.title for finding in WinPEASParser().parse(WINPEAS_OUTPUT).findings
    ]

    assert "AlwaysInstallElevated Enabled" in titles


def test_winpeas_alwaysinstallelevated_maps_t1548() -> None:
    finding = next(
        finding
        for finding in WinPEASParser().parse(WINPEAS_OUTPUT).findings
        if finding.title == "AlwaysInstallElevated Enabled"
    )

    assert finding.mitre_matches[0].technique_id == "T1548.002"


def test_winpeas_sam_readable_is_critical() -> None:
    finding = next(
        finding
        for finding in WinPEASParser().parse(WINPEAS_OUTPUT).findings
        if finding.title == "SAM Database Readable"
    )

    assert finding.severity == Severity.CRITICAL


def test_linpeas_can_parse() -> None:
    assert LinPEASParser().can_parse(LINPEAS_OUTPUT) > 0.85


def test_linpeas_cannot_parse_winpeas() -> None:
    assert LinPEASParser().can_parse(WINPEAS_OUTPUT) == 0.0


def test_linpeas_extracts_suid_binary() -> None:
    titles = [
        finding.title for finding in LinPEASParser().parse(LINPEAS_OUTPUT).findings
    ]

    assert "Exploitable SUID: bash" in titles


def test_linpeas_exploitable_suid_is_high_severity() -> None:
    finding = next(
        finding
        for finding in LinPEASParser().parse(LINPEAS_OUTPUT).findings
        if finding.title == "Exploitable SUID: bash"
    )

    assert finding.severity == Severity.HIGH


def test_linpeas_nopasswd_all_is_critical() -> None:
    finding = next(
        finding
        for finding in LinPEASParser().parse(LINPEAS_OUTPUT).findings
        if finding.title == "Sudo NOPASSWD: ALL"
    )

    assert finding.severity == Severity.CRITICAL


def test_linpeas_cve_detected_maps_t1068() -> None:
    finding = next(
        finding
        for finding in LinPEASParser().parse(LINPEAS_OUTPUT).findings
        if finding.title == "CVE Detected: CVE-2021-4034"
    )

    assert finding.mitre_matches[0].technique_id == "T1068"


def test_linpeas_shadow_readable_is_critical() -> None:
    finding = next(
        finding
        for finding in LinPEASParser().parse(LINPEAS_OUTPUT).findings
        if finding.title == "Shadow File Readable"
    )

    assert finding.severity == Severity.CRITICAL


def test_sqlmap_parser_contract() -> None:
    content = (FIXTURES / "sqlmap_sample.txt").read_text()
    parser = SQLMapParser()

    result = parser.parse(content)

    assert parser.can_parse(content) > 0.9
    assert result.findings[0].title == "SQL injection identified"
    assert parser.parse("parameter").partial is False


def test_generic_c2_parser_extracts_sessions_downloads_and_credentials() -> None:
    content = """
    [server] Listening on mtls://0.0.0.0:8888
    sliver > session 7 from WINTERFELL
    [*] downloaded /home/user/loot/ntds.dit from 10.10.10.10
    NORTH\\alice:Password123!
    """
    parser = GenericC2LogParser()

    c2_result = parser.parse_c2(content)
    result = parser.parse(content)

    assert parser.can_parse(content) > 0.5
    assert c2_result.sessions[0].session_id == "7"
    assert c2_result.downloads[0].path == "/home/user/loot/ntds.dit"
    assert c2_result.credentials[0].username == "alice"
    assert result.credentials[0].secret == "Password123!"
    assert any("C2 session observed" in finding.title for finding in result.findings)


def test_sliver_session_finding_has_mitre_t1071() -> None:
    content = """
    [server] Listening on mtls://0.0.0.0:8888
    sliver > session 7 from WINTERFELL
    """
    result = SliverLogParser().parse(content)
    ttps = [
        match.technique_id
        for finding in result.findings
        for match in finding.mitre_matches
    ]

    assert "T1071.001" in ttps


def test_havoc_session_finding_has_mitre_t1071() -> None:
    content = """
    TeamServer online
    Demon ID abc123 from WINTERFELL
    """
    result = HavocLogParser().parse(content)
    ttps = [
        match.technique_id
        for finding in result.findings
        for match in finding.mitre_matches
    ]

    assert "T1071.001" in ttps


def test_c2_parser_finding_has_affected_host() -> None:
    content = """
    [server] Listening on mtls://0.0.0.0:8888
    sliver > session 7 from WINTERFELL
    """
    result = GenericC2LogParser().parse(content)

    assert result.findings[0].affected_hosts == ["WINTERFELL"]


def test_total_ttp_count_above_95_after_c2_exfil_expansion() -> None:
    assert coverage_summary()["unique_count"] > 95


def test_sliver_and_havoc_c2_parsers_are_framework_specific() -> None:
    sliver_log = """
    sliver > session 7 from WINTERFELL
    [*] downloaded /home/user/loot/ntds.dit from 10.10.10.10
    NORTH\\alice:Password123!
    """
    havoc_log = """
    Havoc Teamserver online
    Demon ID abc123 from WINTERFELL
    [*] downloaded /tmp/loot.txt from 10.10.10.20
    NORTH\\bob:Password123!
    """
    unrelated = "session notes: downloaded report and credential inventory"

    assert isinstance(detect_c2_parser(sliver_log), SliverLogParser)
    assert isinstance(detect_c2_parser(havoc_log), HavocLogParser)
    assert detect_c2_parser(unrelated) is None
    assert SliverLogParser().can_parse(sliver_log) > HavocLogParser().can_parse(
        sliver_log
    )
    assert HavocLogParser().can_parse(havoc_log) > SliverLogParser().can_parse(
        havoc_log
    )

    sliver_result = parser_by_name("sliver").parse(sliver_log)
    havoc_result = parser_by_name("havoc").parse(havoc_log)

    assert sliver_result.tool == "sliver"
    assert sliver_result.credentials[0].username == "alice"
    assert havoc_result.tool == "havoc"
    assert havoc_result.credentials[0].username == "bob"


def test_generic_c2_parser_is_not_registered_for_sliver_or_havoc_aliases() -> None:
    assert type(parser_by_name("sliver")) is SliverLogParser
    assert type(parser_by_name("havoc")) is HavocLogParser


def test_sliver_requires_strong_signal() -> None:
    content = "implant beacon mtls://10.10.10.10 wg://10.10.10.11"

    assert SliverLogParser().can_parse(content) == 0.0


def test_havoc_requires_strong_signal() -> None:
    content = "beacon checkin pivot completed"

    assert HavocLogParser().can_parse(content) == 0.0


def test_c2_low_confidence_warns_user(capsys) -> None:
    detect_parser("sliver > session 7 from WINTERFELL")
    captured = capsys.readouterr()

    assert "C2 parser confidence is low (40%)" in captured.err
    assert "Use --tool sliver or --tool havoc" in captured.err


def test_generic_c2_does_not_match_nmap() -> None:
    content = (FIXTURES / "nmap_sample.xml").read_text()

    assert GenericC2LogParser().can_parse(content) == 0.0


def test_generic_c2_does_not_match_cme() -> None:
    content = (FIXTURES / "cme_sample.txt").read_text()

    assert GenericC2LogParser().can_parse(content) == 0.0

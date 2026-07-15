"""Parser auto-detection."""

from __future__ import annotations

import click
from pydantic import ConfigDict

from pentnote.core.models import PentNoteModel
from pentnote.parsers.base import AbstractParser
from pentnote.parsers.c2.havoc import HavocLogParser
from pentnote.parsers.c2.sliver import SliverLogParser
from pentnote.parsers.universal import UniversalParser
from pentnote.parsers.v1.crackmapexec import CrackMapExecParser
from pentnote.parsers.v1.impacket import SecretsDumpParser
from pentnote.parsers.v1.nmap import NmapParser
from pentnote.parsers.v2.bloodyad import BloodyADParser
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
from pentnote.plugins.loader import load_parser_plugins


class ParserScore(PentNoteModel):
    """Parser confidence score."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    parser: AbstractParser
    score: float


BUILTIN_PARSERS: tuple[type[AbstractParser], ...] = (
    NmapParser,
    CrackMapExecParser,
    SecretsDumpParser,
    BloodHoundParser,
    KerbruteParser,
    LDAPDomainDumpParser,
    GobusterParser,
    FeroxbusterParser,
    NiktoParser,
    NucleiParser,
    SQLMapParser,
    RubeusParser,
    CertipyParser,
    MimikatzParser,
    Enum4linuxParser,
    BloodyADParser,
    ResponderParser,
    WinPEASParser,
    LinPEASParser,
    EvilWinRMParser,
    PowerViewParser,
    SeatbeltParser,
    SmbClientParser,
    LaZagneParser,
    SliverLogParser,
    HavocLogParser,
    UniversalParser,
)


def available_parsers(include_plugins: bool = True) -> list[AbstractParser]:
    """Return all built-in parser strategies."""

    parsers = [parser_cls() for parser_cls in BUILTIN_PARSERS]
    if include_plugins:
        parsers.extend(load_parser_plugins())
    return parsers


def score_parsers(content: str, include_plugins: bool = True) -> list[ParserScore]:
    """Score every parser for the supplied content."""

    scores = []
    for parser in available_parsers(include_plugins=include_plugins):
        try:
            score = parser.can_parse(parser.clean(content))
        except Exception as exc:
            # A parser raising during detection must not be silently
            # indistinguishable from one that simply does not match: surface it
            # on stderr (same channel this module uses for ambiguity warnings)
            # while still scoring 0 so the broken parser cannot win.
            click.echo(
                f"[!] Parser {parser.tool_name!r} errored during detection "
                f"and was skipped: {exc}",
                err=True,
            )
            score = 0.0
        scores.append(ParserScore(parser, score))
    return sorted(scores, key=lambda item: item.score, reverse=True)


def detect_parser(content: str, include_plugins: bool = True) -> ParserScore:
    """Pick the highest-confidence parser."""

    scores = score_parsers(content, include_plugins=include_plugins)
    best = scores[0]
    if best.score <= 0.0:
        raise click.ClickException("No parser recognized this input.")
    if len(scores) > 1 and scores[1].score > 0 and best.score - scores[1].score < 0.15:
        click.echo(
            "[?] Auto-detect ambiguous: "
            f"{best.parser.tool_name} ({best.score:.0%}) vs "
            f"{scores[1].parser.tool_name} ({scores[1].score:.0%}). "
            "Use --tool to be explicit.",
            err=True,
        )
    if best.parser.tool_name in {"sliver", "havoc"} and 0.4 <= best.score <= 0.7:
        click.echo(
            f"[?] C2 parser confidence is low ({best.score:.0%}).\n"
            "    Use --tool sliver or --tool havoc to be explicit.",
            err=True,
        )
    return best


def parser_by_name(name: str, include_plugins: bool = True) -> AbstractParser:
    """Resolve a parser by tool name or alias."""

    requested = name.casefold()
    for parser in available_parsers(include_plugins=include_plugins):
        names = {
            parser.tool_name.casefold(),
            *[alias.casefold() for alias in parser.aliases],
        }
        if requested in names:
            return parser
    raise click.ClickException(f"Unknown parser: {name}")

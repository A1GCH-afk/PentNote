"""Web vulnerability parsers."""

from __future__ import annotations

from pentnote.parsers.v2.certipy import CertipyParser
from pentnote.parsers.v2.enum4linux import Enum4linuxParser
from pentnote.parsers.v2.mimikatz import MimikatzParser
from pentnote.parsers.v2.nikto import NiktoParser
from pentnote.parsers.v2.nuclei import NucleiParser
from pentnote.parsers.v2.rubeus import RubeusParser
from pentnote.parsers.v2.sqlmap import SQLMapParser

__all__ = [
    "CertipyParser",
    "Enum4linuxParser",
    "MimikatzParser",
    "NiktoParser",
    "NucleiParser",
    "RubeusParser",
    "SQLMapParser",
]

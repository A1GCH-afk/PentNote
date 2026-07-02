"""Pydantic models and interface for C2 console log parsing."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import Field, field_validator

from pentnote.core.models import PentNoteModel


class C2Session(PentNoteModel):
    """A live or historical C2 session/beacon."""

    session_id: str = Field(min_length=1)
    operator: str | None = None
    username: str | None = None
    hostname: str | None = None
    address: str | None = None
    platform: str | None = None
    last_seen: str | None = None


class C2Download(PentNoteModel):
    """A file downloaded through a C2 framework."""

    path: str = Field(min_length=1)
    host: str | None = None
    operator: str | None = None
    destination: str | None = None
    timestamp: str | None = None


class C2Credential(PentNoteModel):
    """Credential material extracted from C2 console logs."""

    username: str = Field(min_length=1)
    secret: str = Field(min_length=1)
    secret_type: str = "plaintext"
    host: str | None = None
    domain: str | None = None

    @field_validator("secret_type")
    @classmethod
    def normalize_secret_type(cls, value: str) -> str:
        normalized = value.casefold().strip()
        return (
            normalized
            if normalized in {"plaintext", "ntlm", "kerberos"}
            else "plaintext"
        )


class C2ParseResult(PentNoteModel):
    """Structured C2 log extraction result."""

    framework: str = "generic-c2"
    sessions: list[C2Session] = Field(default_factory=list)
    downloads: list[C2Download] = Field(default_factory=list)
    credentials: list[C2Credential] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class C2Parser(ABC):
    """Interface for C2 framework log parsers."""

    framework = "generic-c2"

    @abstractmethod
    def fingerprint(self, content: str) -> float:
        """Return framework-specific confidence from 0.0 to 1.0."""

    @abstractmethod
    def can_parse(self, content: str) -> float:
        """Return parser confidence from 0.0 to 1.0."""

    @abstractmethod
    def parse_c2(self, content: str) -> C2ParseResult:
        """Extract sessions, downloads, and credentials."""

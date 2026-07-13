"""Ollama-backed structured extraction for Ghost Log."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field, ValidationError, field_validator

from pentnote.ai.ollama import OLLAMA_TIMEOUT_SECONDS, OllamaError


class ExtractedCredential(BaseModel):
    """A credential as extracted from sanitized terminal text by the LLM."""

    username: str
    secret: str
    secret_type: str
    target: str | None = None

    @field_validator("secret_type")
    @classmethod
    def validate_secret_type(cls, value: str) -> str:
        """Normalize secret_type, falling back to "plaintext" for unknown values."""
        allowed = {"plaintext", "ntlm", "kerberos"}
        normalized = value.casefold()
        if normalized not in allowed:
            return "plaintext"
        return normalized


class ExtractedFinding(BaseModel):
    """A finding as extracted from sanitized terminal text by the LLM."""

    title: str
    severity: str
    target: str | None = None
    evidence: str = ""

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        """Normalize severity, falling back to "info" for unknown values."""
        allowed = {"info", "low", "medium", "high", "critical"}
        normalized = value.casefold()
        if normalized not in allowed:
            return "info"
        return normalized


class GhostLogExtraction(BaseModel):
    """Structured result of an Ollama extraction pass over Ghost Log text."""

    credentials: list[ExtractedCredential] = Field(default_factory=list)
    findings: list[ExtractedFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    log_entries: list[str] = Field(default_factory=list)


def extract_findings(text: str, *, model: str = "llama3") -> GhostLogExtraction:
    """Ask Ollama for strict JSON extraction from sanitized terminal text."""

    try:
        import ollama
    except ImportError as exc:
        raise OllamaError(
            "Install PentNote with pentnote[operator] to use Ghost Log."
        ) from exc

    prompt = build_extraction_prompt(text)
    try:
        client = ollama.Client(timeout=OLLAMA_TIMEOUT_SECONDS)
        response = client.generate(model=model, prompt=prompt)
        payload = _json_from_response(str(response.get("response", "")))
        return GhostLogExtraction.model_validate(payload)
    except (Exception, ValidationError) as exc:
        raise OllamaError(str(exc)) from exc


def _json_from_response(value: str) -> dict:
    start = value.find("{")
    end = value.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}
    try:
        return json.loads(value[start : end + 1])
    except json.JSONDecodeError:
        return {}


def build_extraction_prompt(text: str) -> str:
    """Build the strict extraction prompt sent to the local LLM."""

    return (
        "You are an elite penetration testing data parser.\n"
        "Your SOLE purpose is to analyze sanitized terminal output from offensive "
        "security tools and extract actionable intelligence into a STRICT, perfectly "
        "formatted JSON structure.\n\n"
        "You must obey the following rules absolutely:\n"
        "1. OUTPUT ONLY JSON. Do not include greetings, explanations, markdown "
        "formatting (like ```json), or any conversational text.\n"
        "2. DO NOT HALLUCINATE. Only extract credentials, IPs, and findings if they "
        "explicitly exist in the provided text.\n"
        "3. If a field cannot be determined, use null. If no items are found for a "
        "category, return an empty array [].\n"
        "4. Ensure all quotes inside the evidence strings are properly escaped.\n\n"
        "You must conform exactly to the following JSON schema:\n\n"
        "{\n"
        '  "credentials": [\n'
        "    {\n"
        '      "username": "string (extracted username)",\n'
        '      "secret": "string (extracted password or hash)",\n'
        '      "secret_type": "plaintext | ntlm | kerberos",\n'
        '      "target": "string (IP or domain, if known, else null)"\n'
        "    }\n"
        "  ],\n"
        '  "findings": [\n'
        "    {\n"
        '      "title": "string (short description of the vulnerability or success)",\n'
        '      "severity": "info | low | medium | high | critical",\n'
        '      "target": "string (IP or domain)",\n'
        '      "evidence": "string (exact command output proving the finding)"\n'
        "    }\n"
        "  ],\n"
        '  "notes": [\n'
        '    "string (a single sentence actionable observation, e.g., '
        "'WinRM is open on 192.168.56.11')\"\n"
        "  ]\n"
        "}\n\n"
        "Input terminal chunk to analyze:\n"
        f"{text[:8000]}"
    )

"""Local Ollama summary support."""

from __future__ import annotations

OLLAMA_TIMEOUT_SECONDS = 120.0
"""Client-side timeout for local Ollama calls.

Prevents the caller (e.g. the Ghost Log daemon) from blocking indefinitely if
the Ollama server stalls or never responds.
"""


class OllamaError(RuntimeError):
    """Raised when Ollama summary generation fails."""


def summarize_text(content: str, model: str = "llama3") -> str:
    """Summarize raw tool output with a local Ollama model.

    Args:
        content: Raw tool output.
        model: Local Ollama model name.

    Returns:
        A concise summary string.

    Raises:
        OllamaError: If the optional ``ollama`` dependency is unavailable or fails.
    """

    try:
        import ollama
    except ImportError as exc:
        raise OllamaError(
            "Install PentNote with pentnote[operator] to use --ai-summary."
        ) from exc

    prompt = (
        "Summarize this pentest tool output in three concise bullets, "
        "focusing on security impact and next actions.\n\n"
        f"{content[:12000]}"
    )
    try:
        client = ollama.Client(timeout=OLLAMA_TIMEOUT_SECONDS)
        response = client.generate(model=model, prompt=prompt)
    except Exception as exc:
        raise OllamaError(
            "Install PentNote with pentnote[operator] and ensure Ollama is running: "
            f"{exc}"
        ) from exc
    return str(response.get("response", "")).strip()

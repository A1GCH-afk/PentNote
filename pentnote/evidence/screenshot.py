"""Screen capture support for visual evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pentnote.core.engagement import Engagement
from pentnote.core.models import PentNoteModel
from pentnote.evidence.linker import append_evidence_link
from pentnote.evidence.ocr import extract_text
from pentnote.workspace.store import WorkspaceStore


class ScreenshotResult(PentNoteModel):
    """Evidence capture result."""

    attachment_path: Path
    note_path: Path
    ocr_text: str


def capture_and_link_screenshot(
    engagement: Engagement, target: str
) -> ScreenshotResult:
    """Capture the current screen, save it, OCR it, and link it to a host note."""

    attachment_path = capture_screen(engagement.root / "attachments")
    ocr_text = extract_text(attachment_path)
    note_path = append_evidence_link(
        engagement.notes_dir,
        target,
        attachment_path.name,
        ocr_text=ocr_text,
    )
    WorkspaceStore(engagement.root).add_note(
        {
            "target": target,
            "target_type": "host",
            "finding": None,
            "content": f"Visual evidence captured: ![[{attachment_path.name}]]",
            "date": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "tags": ["evidence", "screenshot"],
        }
    )
    return ScreenshotResult(
        attachment_path=attachment_path, note_path=note_path, ocr_text=ocr_text
    )


def capture_screen(attachments_dir: Path) -> Path:
    """Capture all monitors into a timestamped PNG using mss."""

    try:
        import mss
        import mss.tools
    except ImportError as exc:
        raise RuntimeError(
            "Install PentNote with pentnote[operator] to use snap."
        ) from exc

    attachments_dir.mkdir(parents=True, exist_ok=True)
    path = attachments_dir / f"screenshot_{_timestamp()}.png"
    with mss.mss() as screen:
        monitor = screen.monitors[0]
        image = screen.grab(monitor)
        mss.tools.to_png(image.rgb, image.size, output=str(path))
    return path


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

"""Optional OCR support for screenshot evidence."""

from __future__ import annotations

from pathlib import Path


def extract_text(image_path: Path) -> str:
    """Extract OCR text when pytesseract is installed and configured."""

    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return ""
    try:
        with Image.open(image_path) as image:
            return str(pytesseract.image_to_string(image)).strip()
    except Exception:
        return ""

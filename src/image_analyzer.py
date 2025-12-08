"""
Image Analyzer Module
Uses OCR to extract text from images for analysis.
"""

import logging
from typing import List
from io import BytesIO

try:
    from PIL import Image
    import pytesseract
except ImportError:
    Image = None
    pytesseract = None

from src.config import TESSERACT_CMD_PATH


class ImageAnalyzer:
    """
    Analyzes images to extract text using OCR.
    """

    def __init__(self):
        """Initialize the image analyzer."""
        self.enabled = False
        if Image and pytesseract:
            self.enabled = True
            if TESSERACT_CMD_PATH:
                pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD_PATH

    def extract_text_from_images(self, image_attachments: List[dict]) -> str:
        """
        Extract text from a list of image attachment dictionaries.

        Args:
            image_attachments: List of dicts with 'content' (bytes) and
            'filename'.

        Returns:
            Concatenated string of extracted text.
        """
        if not self.enabled or not image_attachments:
            return ""

        extracted_text = []

        for img_data in image_attachments:
            try:
                content = img_data.get("content")
                if not content:
                    continue

                image = Image.open(BytesIO(content))
                text = pytesseract.image_to_string(image)
                if text.strip():
                    extracted_text.append(
                        f"--- Extracted from "
                        f"{img_data.get('filename', 'image')} "
                        f"---\n{text}"
                    )
            except Exception as e:
                logging.warning(
                    f"OCR failed for image "
                    f"{img_data.get('filename')}: {e}"
                )

        return "\n\n".join(extracted_text)

"""
Email Parser Module
Extracts key information from raw or EML-format emails.
"""

import email
from email import policy
import re
from urllib.parse import urlparse
from typing import Dict, List
from pathlib import Path

try:
    from urlextract import URLExtract
except ImportError:
    URLExtract = None


class EmailParser:
    """
    Parse email files (raw or EML format) and extract key metadata.
    """

    def __init__(self):
        """Initialize the email parser."""
        self.url_extractor = URLExtract() if URLExtract else None

    def parse_email(self, email_path: str) -> Dict:
        """
        Parse an email file and extract key information.

        Args:
            email_path: Path to the email file (raw or EML format)

        Returns:
            Dictionary containing parsed email data
        """
        email_path = Path(email_path)

        if not email_path.exists():
            raise FileNotFoundError(f"Email file not found: {email_path}")

        try:
            with open(email_path, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
        except Exception as e:
            raise ValueError(f"Failed to parse email: {e}")

        return self._extract_email_data(msg)

    def parse_email_from_string(self, email_string: str) -> Dict:
        """
        Parse an email from a string.

        Args:
            email_string: Email content as string

        Returns:
            Dictionary containing parsed email data
        """
        try:
            msg = email.message_from_string(
                email_string, policy=policy.default
            )
        except Exception as e:
            raise ValueError(f"Failed to parse email string: {e}")

        return self._extract_email_data(msg)

    def _extract_email_data(self, msg) -> Dict:
        """
        Extract all relevant data from email message object.

        Args:
            msg: Email message object

        Returns:
            Dictionary with extracted email data
        """
        return {
            "sender": self._extract_sender(msg),
            "recipient": self._extract_recipient(msg),
            "subject": self._get_header(msg, "Subject", ""),
            "date": self._get_header(msg, "Date", ""),
            "headers": self._extract_headers(msg),
            "body": self._extract_body(msg),
            "urls": self._extract_urls(msg),
            "attachments": self._extract_attachments(msg),
            "is_html": self._is_html_email(msg),
            "reply_to": self._get_header(msg, "Reply-To", ""),
        }

    def _extract_sender(self, msg) -> str:
        """Extract sender email address from From header."""
        from_header = self._get_header(msg, "From", "")
        if not from_header:
            return ""

        # Parse email address from "Name <email@domain.com>" format
        match = re.search(r"<(.+?)>", from_header)
        if match:
            return match.group(1).lower()

        # If no angle brackets, assume the entire header is the email
        return from_header.strip().lower()

    def _extract_recipient(self, msg) -> str:
        """Extract recipient email address from To header."""
        to_header = self._get_header(msg, "To", "")
        if not to_header:
            return ""

        match = re.search(r"<(.+?)>", to_header)
        if match:
            return match.group(1).lower()

        return to_header.strip().lower()

    def _get_header(self, msg, header_name: str, default: str = "") -> str:
        """Safely get header value."""
        try:
            value = msg.get(header_name, default)
            return str(value).strip() if value else default
        except Exception:
            return default

    def _extract_headers(self, msg) -> Dict[str, str]:
        """Extract all headers from email."""
        headers = {}
        for key, value in msg.items():
            try:
                headers[key] = str(value).strip()
            except Exception:
                pass
        return headers

    def _extract_body(self, msg) -> str:
        """Extract email body (text and/or HTML)."""
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()

                if content_type == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode(
                            "utf-8", errors="ignore"
                        )
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        body += part.get_payload(decode=True).decode(
                            "utf-8", errors="ignore"
                        )
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                body = msg.get_payload()

        return body.strip()

    def _extract_urls(self, msg) -> List[Dict]:
        """
        Extract all URLs from email body and HTML.

        Returns:
            List of dictionaries containing URL and context
        """
        urls = []
        body = self._extract_body(msg)

        # Extract URLs from body
        if self.url_extractor:
            extracted_urls = self.url_extractor.find_urls(body)
            for url in extracted_urls:
                urls.append(self._url_info(url))
        else:
            # Fallback to regex-based extraction
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            matches = re.findall(url_pattern, body)
            for url in matches:
                urls.append(self._url_info(url))

        # Extract URLs from href attributes if HTML
        href_pattern = r'href=["\'](https?://[^\s"\'<>]+)'
        href_matches = re.findall(href_pattern, body)
        for url in href_matches:
            urls.append(self._url_info(url))

        # Extract URLs from text vs displayed link mismatches (anchor tags)
        # Format: <a href="real_url">displayed_text</a>
        anchor_pattern = (
            r'<a\s+href=["\'](https?://[^\s"\'<>]+)["\']>([^<]+)</a>'
        )
        anchors = re.findall(anchor_pattern, body, re.IGNORECASE)
        for real_url, display_text in anchors:
            url_info = self._url_info(real_url)
            url_info["displayed_text"] = display_text.strip()
            urls.append(url_info)

        # Remove duplicates
        unique_urls = []
        seen = set()
        for url_obj in urls:
            url_key = url_obj["url"]
            if url_key not in seen:
                seen.add(url_key)
                unique_urls.append(url_obj)

        return unique_urls

    def _url_info(self, url: str) -> Dict:
        """Create URL info dictionary."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            domain = ""

        return {
            "url": url,
            "domain": domain,
            "scheme": parsed.scheme if "parsed" in locals() else "",
            "path": parsed.path if "parsed" in locals() else "",
        }

    def _extract_attachments(self, msg) -> List[Dict]:
        """
        Extract attachment information.

        Returns:
            List of dictionaries with attachment metadata
        """
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename("")
                    if filename:
                        attachments.append(
                            {
                                "filename": filename,
                                "size": (
                                    len(part.get_payload(decode=True))
                                    if part.get_payload()
                                    else 0
                                ),
                                "content_type": part.get_content_type(),
                            }
                        )

        return attachments

    def _is_html_email(self, msg) -> bool:
        """Check if email contains HTML content."""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    return True
        return False

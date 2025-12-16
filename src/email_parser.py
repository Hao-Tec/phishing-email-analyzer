"""
Email Parser Module
Extracts key information from raw or EML-format emails.
"""

import email
from email import policy
import re
import gzip
from urllib.parse import urlparse
from typing import Dict, List
from pathlib import Path
from email.utils import parseaddr
from bs4 import BeautifulSoup

try:
    from urlextract import URLExtract
except ImportError:
    URLExtract = None

try:
    import extract_msg
except ImportError:
    extract_msg = None


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

        raw_content = b""
        msg = None

        try:
            # Handle .eml.gz
            if email_path.suffix.lower() == ".gz":
                with gzip.open(email_path, "rb") as f:
                    raw_content = f.read()
                with gzip.open(email_path, "rb") as f:
                    raw_content = f.read()
                    msg = email.message_from_bytes(
                        raw_content, policy=policy.default
                    )

            # Handle .msg (Outlook)
            elif email_path.suffix.lower() == ".msg":
                if extract_msg:
                    msg_obj = extract_msg.Message(email_path)
                    # Convert to standard email object structure
                    # or extract directly. For consistency,
                    # we'll try to map it to our structure
                    # manually since it's not a python object.
                    return self._extract_msg_data(msg_obj)
                else:
                    raise ImportError(
                        "extract-msg library needed for .msg files"
                    )

            # Handle standard .eml / .txt
            else:
                with open(email_path, "rb") as f:
                    raw_content = f.read()
                    msg = email.message_from_bytes(
                        raw_content, policy=policy.default
                    )

        except Exception as e:
            raise ValueError(f"Failed to parse email: {e}")

        data = self._extract_email_data(msg)
        data["raw_content"] = raw_content  # Add raw content for DKIM
        return data

    def parse_email_from_string(self, email_string: str) -> Dict:
        """
        Parse an email from a string.

        Args:
            email_string: Email content as string

        Returns:
            Dictionary containing parsed email data
        """
        try:
            # Attempt to encode back to bytes for raw
            # consistency if possible
            raw_content = email_string.encode(
                "utf-8", errors="ignore"
            )
            msg = email.message_from_string(
                email_string, policy=policy.default
            )
        except Exception as e:
            raise ValueError(f"Failed to parse email string: {e}")

        data = self._extract_email_data(msg)
        data["raw_content"] = raw_content
        return data

    def _extract_msg_data(self, msg_obj) -> Dict:
        """
        Extract data specifically from an Outlook .msg object.
        """
        body = msg_obj.body
        html_body = msg_obj.htmlBody

        # Prefer HTML if available for URL extraction
        content_body = (
            html_body.decode("utf-8", errors="ignore")
            if html_body
            else (body or "")
        )
        is_html = bool(html_body)

        sender = msg_obj.sender
        to = msg_obj.to
        subject = msg_obj.subject
        date = msg_obj.date
        headers = {k: v for k, v in msg_obj.header.items()}

        urls = self._extract_urls(
            None, content_body, is_html
        )  # msg object not needed for regex extraction

        # Attachments in msg are tricky, simple extraction
        attachments = []
        for att in msg_obj.attachments:
            # Basic info
            attachments.append(
                {
                    "filename": att.longFilename or att.shortFilename,
                    "size": len(att.data) if hasattr(att, "data") else 0,
                    "content_type": "application/octet-stream",  # Generic
                    "content": att.data if hasattr(att, "data") else None,
                }
            )

        return {
            "sender": str(sender),
            "recipient": str(to),
            "subject": str(subject),
            "date": str(date),
            "headers": headers,
            "body": body or "",
            "urls": urls,
            "attachments": attachments,
            "is_html": is_html,
            "reply_to": headers.get("Reply-To", ""),
            "raw_content": None,  # .msg parsing doesn't easily give original
            # raw MIME bytes suitable for DKIM verify
        }

    def _extract_email_data(self, msg) -> Dict:
        """
        Extract all relevant data from email message object.

        Args:
            msg: Email message object

        Returns:
            Dictionary with extracted email data
        """
        body, is_html = self._extract_body(msg)
        return {
            "sender": self._extract_sender(msg),
            "recipient": self._extract_recipient(msg),
            "subject": self._get_header(msg, "Subject", ""),
            "date": self._get_header(msg, "Date", ""),
            "headers": self._extract_headers(msg),
            "body": body,
            "urls": self._extract_urls(msg, body, is_html),
            "attachments": self._extract_attachments(msg),
            "is_html": is_html,
            "reply_to": self._get_header(msg, "Reply-To", ""),
        }

    def _extract_sender(self, msg) -> str:
        """Extract sender email address from From header."""
        from_header = self._get_header(msg, "From", "")
        if not from_header:
            return ""

        # improved parsing
        _, email_address = parseaddr(from_header)
        return email_address.lower() if email_address else from_header.lower()

    def _extract_recipient(self, msg) -> str:
        """Extract recipient email address from To header."""
        to_header = self._get_header(msg, "To", "")
        if not to_header:
            return ""

        _, email_address = parseaddr(to_header)
        return email_address.lower() if email_address else to_header.lower()

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

    def _extract_body(self, msg) -> tuple[str, bool]:
        """
        Extract email body (text and/or HTML).
        Returns tuple (body_content, is_html)
        """
        body = ""
        is_html = False

        if msg.is_multipart():
            # Prioritize HTML then Text
            html_part = None
            text_part = None

            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    html_part = part
                elif content_type == "text/plain":
                    text_part = part

            if html_part:
                try:
                    body = html_part.get_payload(decode=True).decode(
                        "utf-8", errors="ignore"
                    )
                    is_html = True
                except Exception:
                    pass
            elif text_part:
                try:
                    body = text_part.get_payload(decode=True).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    pass
        else:
            try:
                # If not multipart, check content type
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="ignore")
                else:
                    # Fallback if decode=True returns None
                    # (sometimes happens with empty bodies)
                    body = str(msg.get_payload())

                is_html = content_type == "text/html"
            except Exception:
                body = str(msg.get_payload())

        return body.strip(), is_html

    def _extract_urls(self, msg, body: str, is_html: bool) -> List[Dict]:
        """
        Extract all URLs from email body and HTML.

        Returns:
            List of dictionaries containing URL and context
        """
        urls = []

        # If HTML, use BeautifulSoup
        soup = None
        if is_html:
            try:
                soup = BeautifulSoup(body, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    text = a_tag.get_text(strip=True)

                    url_info = self._url_info(href)
                    if text:
                        url_info["displayed_text"] = text
                    urls.append(url_info)
            except Exception:
                pass  # Fallback to regex if BS4 fails

        # Regex extraction for plain text or as backup
        # OPTIMIZATION: For HTML, scan extracted text/attributes instead of raw HTML
        # Scanning raw HTML with urlextract is very slow (redundant parsing).
        # We extract visible text, scripts, and all attributes to ensure coverage
        # while significantly reducing the input size for the regex engine.
        text_to_scan = body
        if is_html and soup:
            try:
                chunks = []
                # 1. Visible Text
                chunks.append(soup.get_text(" ", strip=True))

                # 2. Scripts and Styles (Hidden content)
                for tag in soup(["script", "style"]):
                    if tag.string:
                        chunks.append(tag.string)

                # 3. Attributes (src, action, data-*, etc.)
                # Iterating tags is faster than regex-scanning the full raw string
                for tag in soup.find_all(True):
                    for val in tag.attrs.values():
                        if isinstance(val, str):
                            chunks.append(val)
                        elif isinstance(val, list):
                            chunks.append(" ".join(val))

                text_to_scan = " ".join(chunks)
            except Exception:
                pass  # Fallback to full body if processing fails

        if self.url_extractor:
            extracted_urls = self.url_extractor.find_urls(text_to_scan)
            for url in extracted_urls:
                urls.append(self._url_info(url))
        else:
            # Fallback to regex-based extraction
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            matches = re.findall(url_pattern, body)
            for url in matches:
                urls.append(self._url_info(url))

        # Remove duplicates based on URL
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
                        # Extract content for OCR if possible
                        content = part.get_payload(decode=True)
                        attachments.append(
                            {
                                "filename": filename,
                                "size": len(content) if content else 0,
                                "content_type": part.get_content_type(),
                                "content": content,  # Added content for OCR
                            }
                        )

        return attachments

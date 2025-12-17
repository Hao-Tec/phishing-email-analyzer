"""
URL Scraper Module
Fetches and extracts text content from URLs for analysis.
"""

import requests
import logging
from bs4 import BeautifulSoup
from typing import Dict
import socket
import ipaddress
from urllib.parse import urlparse, urljoin


class URLScraper:
    """
    Scrapes content from URLs safely for AI analysis.
    """

    def __init__(self, timeout: int = 5, max_content_length: int = 2000):
        """
        Initialize scraper.

        Args:
            timeout: Request timeout in seconds
            max_content_length: Max characters to return for analysis
        """
        self.timeout = timeout
        self.max_content_length = max_content_length
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        }

    def _is_safe_url(self, url: str) -> bool:
        """
        Validates that the URL resolves to a public IP address.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False

            # Resolve IP(s) - check all returned addresses
            # Use getaddrinfo to support both IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, None)

            for family, type, proto, canonname, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                # Check for Private, Loopback, Link Local, and Reserved
                if (ip.is_private or
                    ip.is_loopback or
                    ip.is_link_local or
                    ip.is_reserved or
                    ip.is_unspecified):
                    return False

            return True
        except Exception:
            # If DNS fails or other errors, assume unsafe/unreachable
            return False

    def scrape(self, url: str) -> Dict[str, str]:
        """
        Fetch URL and extract title and body text.

        Args:
            url: URL to scrape

        Returns:
            Dict with 'title' and 'text', or None if failed.
        """
        try:
            # SSRF Protection: Manual redirect handling
            with requests.Session() as session:
                current_url = url
                response = None

                for _ in range(5):  # Limit redirects
                    if not self._is_safe_url(current_url):
                        raise ValueError("Potential SSRF detected: blocked private/local IP")

                    response = session.get(
                        current_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    if response.is_redirect:
                        location = response.headers.get('Location')
                        if location:
                            current_url = urljoin(current_url, location)
                            continue
                    break

                # If still redirecting after loop, or if response is None
                if response is None:
                     raise ValueError("Request failed")

                if response.is_redirect:
                     raise ValueError("Too many redirects")

                response.raise_for_status()

                # Limit response size to prevent DoS/memory issues for huge pages
                if len(response.content) > 2 * 1024 * 1024:  # 2MB limit
                    logging.warning(
                        f"Page content too large for {url}, scraping partial."
                    )

                soup = BeautifulSoup(response.content, "html.parser")

            # Extract title
            title = (
                soup.title.string.strip()
                if soup.title and soup.title.string
                else "No Title"
            )

            # Extract text
            # Kill all script and style elements
            for script in soup(["script", "style", "meta", "noscript"]):
                script.extract()  # rip it out

            # Get text
            text = soup.get_text()

            # Break into lines and remove leading and trailing space on each
            lines = (line.strip() for line in text.splitlines())
            # Break multi-headlines into a line each
            chunks = (
                phrase.strip() for line in lines for phrase in line.split("  ")
            )
            # Drop blank lines
            text = "\n".join(chunk for chunk in chunks if chunk)

            # Truncate
            if len(text) > self.max_content_length:
                text = text[: self.max_content_length] + "... (truncated)"

            return {"url": url, "title": title, "text": text}

        except Exception as e:
            # Sanitize error message for cleaner terminal output
            error_msg = str(e)
            if (
                "NameResolutionError" in error_msg
                or "getaddrinfo failed" in error_msg
            ):
                short_msg = "DNS resolution failed (Domain not found)"
            elif "ConnectTimeout" in error_msg:
                short_msg = "Connection timed out"
            else:
                # Keep it short, avoid full traceback text
                short_msg = str(e).split('(')[0].strip()

            # Return error as result instead of logging it to console
            return {"url": url, "error": short_msg, "title": "Scan Failed"}

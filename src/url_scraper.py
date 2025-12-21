"""
URL Scraper Module
Fetches and extracts text content from URLs for analysis.
"""

import requests
import logging
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import Dict


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

    def _is_safe_ip(self, hostname: str) -> bool:
        """
        Resolves hostname (IPv4/IPv6) and checks if it points to a private/reserved IP.
        """
        try:
            # Use getaddrinfo to get all IPs (IPv4 and IPv6)
            # family=0 means both IPv4 and IPv6
            # type=socket.SOCK_STREAM ensures we check what HTTP would use
            addr_info = socket.getaddrinfo(hostname, None, family=0, type=socket.SOCK_STREAM)

            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip)

                # Check for private, loopback, link-local, or reserved IPs
                if (ip_obj.is_private or
                    ip_obj.is_loopback or
                    ip_obj.is_link_local or
                    ip_obj.is_reserved or
                    str(ip_obj).startswith('169.254.')): # Explicit check for link-local/AWS metadata
                    return False
            return True
        except Exception:
            # If we can't resolve it, it might be safer to block or let requests fail naturally.
            # But here we probably want to fail if we can't verify safety.
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
            # SSRF Protection: Check the initial URL
            parsed_url = urlparse(url)
            if not parsed_url.hostname:
                 return {"url": url, "error": "Invalid URL", "title": "Scan Failed"}

            if not self._is_safe_ip(parsed_url.hostname):
                return {"url": url, "error": "Blocked: Resolved to private/restricted IP", "title": "Scan Blocked"}

            # Manual redirect handling to check intermediate URLs
            current_url = url
            session = requests.Session()
            response = None

            # Limit redirects to avoid infinite loops
            for _ in range(5):
                response = session.get(
                    current_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True # Use stream to check headers/size before download
                )

                if response.is_redirect:
                    next_url = response.headers.get('Location')
                    if not next_url:
                        break

                    # Handle relative redirects correctly using current_url
                    next_url = urljoin(current_url, next_url)

                    # Check next URL
                    next_parsed = urlparse(next_url)
                    if next_parsed.hostname and not self._is_safe_ip(next_parsed.hostname):
                        return {"url": url, "error": "Blocked: Redirected to private/restricted IP", "title": "Scan Blocked"}

                    current_url = next_url
                else:
                    break

            if response is None:
                 return {"url": url, "error": "No response", "title": "Scan Failed"}

            # Check final response status
            response.raise_for_status()

            # Limit response size to prevent DoS/memory issues for huge pages
            if int(response.headers.get('content-length', 0)) > 2 * 1024 * 1024:
                 logging.warning(f"Page content too large for {url}, scraping partial.")

            # Read content (streamed)
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 2 * 1024 * 1024:
                    break

            soup = BeautifulSoup(content, "html.parser")

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

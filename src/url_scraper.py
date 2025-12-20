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
from typing import Dict, Optional


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
        Check if the URL resolves to a safe (public) IP address.
        Blocks private, loopback, link-local, and reserved ranges.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False

            # Resolve hostname to IP
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                return False  # Cannot resolve, unsafe to proceed

            ip_obj = ipaddress.ip_address(ip)

            # Block dangerous ranges
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                logging.warning(f"Blocked SSRF attempt to {url} ({ip})")
                return False

            return True

        except Exception:
            return False

    def scrape(self, url: str) -> Dict[str, str]:
        """
        Fetch URL and extract title and body text.
        Includes SSRF protection by verifying IP and handling redirects manually.

        Args:
            url: URL to scrape

        Returns:
            Dict with 'title' and 'text', or error info.
        """
        try:
            # Manual redirect handling (max 5)
            current_url = url
            response = None

            for _ in range(5):
                # Check IP safety before every request
                if not self._is_safe_url(current_url):
                    return {
                        "url": url,
                        "error": "Access denied (Blocked IP range)",
                        "title": "Security Block"
                    }

                response = requests.get(
                    current_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False, # Disable auto-redirects
                    stream=True # Don't download full content yet
                )

                if response.is_redirect:
                    location = response.headers.get('Location')
                    if location:
                        # Handle relative redirects
                        current_url = urljoin(current_url, location)
                        continue

                break # Not a redirect, we are done

            if not response:
                return {"url": url, "error": "Request failed", "title": "Scan Failed"}

            # Final check just in case
            if response.is_redirect:
                 return {"url": url, "error": "Too many redirects", "title": "Scan Failed"}

            # Check status of final response
            response.raise_for_status()

            # Limit response size
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 2 * 1024 * 1024: # 2MB limit
                    logging.warning(f"Page content too large for {url}, scraping partial.")
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
                script.extract()

            # Get text
            text = soup.get_text()

            # Cleanup text
            lines = (line.strip() for line in text.splitlines())
            chunks = (
                phrase.strip() for line in lines for phrase in line.split("  ")
            )
            text = "\n".join(chunk for chunk in chunks if chunk)

            # Truncate
            if len(text) > self.max_content_length:
                text = text[: self.max_content_length] + "... (truncated)"

            return {"url": url, "title": title, "text": text}

        except Exception as e:
            # Sanitize error message
            error_msg = str(e)
            if (
                "NameResolutionError" in error_msg
                or "getaddrinfo failed" in error_msg
            ):
                short_msg = "DNS resolution failed (Domain not found)"
            elif "ConnectTimeout" in error_msg:
                short_msg = "Connection timed out"
            else:
                short_msg = str(e).split('(')[0].strip()

            return {"url": url, "error": short_msg, "title": "Scan Failed"}

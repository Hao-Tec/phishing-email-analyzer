"""
URL Scraper Module
Fetches and extracts text content from URLs for analysis.
"""

import requests
import logging
import socket
import ipaddress
from urllib.parse import urlparse
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

    def _validate_url(self, url: str) -> None:
        """
        Validates that the URL does not point to a private/local IP.
        SSRF protection. Raises ValueError if unsafe.
        Raises ValueError if unsafe.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                raise ValueError("Invalid URL: No hostname")

            # Resolve hostname to IP
            try:
                ip_list = socket.getaddrinfo(hostname, None)
                # Check all resolved IPs
                for item in ip_list:
                    ip_str = item[4][0]
                    ip = ipaddress.ip_address(ip_str)

                    if (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_reserved
                        or ip.is_multicast
                    ):
                        raise ValueError(
                            f"Blocked access to private/local IP: {ip_str}"
                        )

            except socket.gaierror:
                # If we can't resolve it, we can't verify it, so it might
                # be safer to block but for scraping purposes, if it doesn't
                # resolve, the request will fail anyway.
                # However, to be strict, we let the request fail
                # naturally or raise here.
                pass

        except Exception as e:
            # Re-raise known ValueErrors, wrap others
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"URL validation failed: {str(e)}")

    def scrape(self, url: str) -> Dict[str, str]:
        """
        Fetch URL and extract title and body text.

        Implements SSRF protection by verifying IPs and
        handling redirects manually.

        Args:
            url: URL to scrape

        Returns:
            Dict with 'title' and 'text', or None if failed.
        """
        try:
            # Initial validation
            self._validate_url(url)

            # Manual redirect handling to validate each hop
            current_url = url
            response = None
            redirect_limit = 5

            with requests.Session() as session:
                for _ in range(redirect_limit):
                    response = session.get(
                        current_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True,  # prevent large content download
                    )

                    if response.is_redirect:
                        location = response.headers.get("Location")
                        if not location:
                            break

                        # Handle relative redirects
                        if location.startswith("/"):
                            parsed_current = urlparse(current_url)
                            scheme = parsed_current.scheme
                            netloc = parsed_current.netloc
                            location = f"{scheme}://{netloc}{location}"

                        # Validate the next hop
                        self._validate_url(location)
                        current_url = location
                        response.close()  # close previous connection
                    else:
                        break

            if not response:
                raise ValueError("Failed to get response")

            # Limit response size
            # We need to read content now since we used stream=True
            content_len = int(response.headers.get("content-length", 0))
            if content_len > 2 * 1024 * 1024:
                logging.warning(f"Page content header too large for {url}")
                # We could abort here, but let's try reading safely up to limit

            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 2 * 1024 * 1024:
                    logging.warning(
                        f"Page content too large for {url}, scraping partial."
                    )
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

            # Break into lines and remove leading and trailing space on each
            lines = (line.strip() for line in text.splitlines())
            # Break multi-headlines into a line each
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            # Drop blank lines
            text = "\n".join(chunk for chunk in chunks if chunk)

            # Truncate
            if len(text) > self.max_content_length:
                text = text[: self.max_content_length] + "... (truncated)"

            return {"url": url, "title": title, "text": text}

        except Exception as e:
            # Sanitize error message
            error_msg = str(e)
            if "NameResolutionError" in error_msg or "getaddrinfo failed" in error_msg:
                short_msg = "DNS resolution failed (Domain not found)"
            elif "ConnectTimeout" in error_msg:
                short_msg = "Connection timed out"
            elif "Blocked access" in error_msg:
                short_msg = "Access denied (Security restricted)"
            else:
                short_msg = str(e).split("(")[0].strip()

            return {"url": url, "error": short_msg, "title": "Scan Failed"}

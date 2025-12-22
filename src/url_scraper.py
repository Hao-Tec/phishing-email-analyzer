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

    def scrape(self, url: str) -> Dict[str, str]:
        """
        Fetch URL and extract title and body text.

        Args:
            url: URL to scrape

        Returns:
            Dict with 'title' and 'text', or None if failed.
        """
        try:
            target_url = url
            # SSRF Protection: Manually follow redirects (limit 5) & check IPs
            for _ in range(5):
                host = urlparse(target_url).hostname
                if not host: raise ValueError("Invalid URL")

                # Resolve & validate IP (blocks private/loopback/link-local)
                for _, _, _, _, (ip, *_) in socket.getaddrinfo(host, None):
                    if ipaddress.ip_address(ip).is_private:
                        raise ValueError(f"Blocked access to sensitive IP: {ip}")

                resp = requests.get(target_url, headers=self.headers,
                                  timeout=self.timeout, allow_redirects=False, stream=True)

                if 300 <= resp.status_code < 400:
                    if 'Location' not in resp.headers: break
                    target_url = urljoin(target_url, resp.headers['Location'])
                    continue
                break
            else:
                raise ValueError("Too many redirects")

            resp.raise_for_status()
            # Enforce 2MB limit on content download
            content = b""
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 2 * 1024 * 1024:
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

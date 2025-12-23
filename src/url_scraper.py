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

    def _is_safe_url(self, url: str) -> bool:
        """Checks if URL resolves to a safe (non-local) IP address."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False

            # Resolve hostname to IPs (IPv4/IPv6)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            addr_info = socket.getaddrinfo(hostname, port)

            for _, _, _, _, sockaddr in addr_info:
                ip_addr = sockaddr[0]
                ip = ipaddress.ip_address(ip_addr)

                # Block private, loopback, link-local, and multicast/reserved
                if (ip.is_private or ip.is_loopback or
                    ip.is_link_local or ip.is_reserved):
                    logging.warning(f"Blocked SSRF attempt to {url} ({ip_addr})")
                    return False
            return True
        except Exception as e:
            logging.warning(f"URL safety check failed for {url}: {e}")
            return False

    def scrape(self, url: str) -> Dict[str, str]:
        """
        Fetch URL and extract title and body text.
        """
        try:
            # Manual redirect handling to prevent SSRF via redirects
            current_url = url
            response = None

            for _ in range(5):  # Max 5 redirects
                if not self._is_safe_url(current_url):
                    return {"url": url, "error": "Security check failed (Blocked IP)", "title": "Scan Blocked"}

                response = requests.get(
                    current_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True
                )

                if response.is_redirect:
                    location = response.headers.get('Location')
                    if location:
                        current_url = urljoin(current_url, location)
                        continue

                response.raise_for_status()
                break # Success

            if not response or response.is_redirect:
                 return {"url": url, "error": "Too many redirects or failed", "title": "Scan Failed"}

            # Limit response size
            if len(response.content) > 2 * 1024 * 1024:  # 2MB limit
                logging.warning(f"Page content too large for {url}, scraping partial.")

            soup = BeautifulSoup(response.content, "html.parser")

            # Extract title
            title = (
                soup.title.string.strip()
                if soup.title and soup.title.string
                else "No Title"
            )

            # Extract text
            for script in soup(["script", "style", "meta", "noscript"]):
                script.extract()

            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = "\n".join(chunk for chunk in chunks if chunk)

            if len(text) > self.max_content_length:
                text = text[: self.max_content_length] + "... (truncated)"

            return {"url": url, "title": title, "text": text}

        except Exception as e:
            error_msg = str(e)
            if "NameResolutionError" in error_msg or "getaddrinfo failed" in error_msg:
                short_msg = "DNS resolution failed (Domain not found)"
            elif "ConnectTimeout" in error_msg:
                short_msg = "Connection timed out"
            else:
                short_msg = str(e).split('(')[0].strip()

            return {"url": url, "error": short_msg, "title": "Scan Failed"}

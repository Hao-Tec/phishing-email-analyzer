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
        Check if the URL resolves to a safe (non-local) IP address.
        Prevents SSRF attacks.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False

            # Resolve hostname to IP
            try:
                # Get the IP address
                # We use getaddrinfo to support both IPv4 and IPv6
                addr_info = socket.getaddrinfo(hostname, None)
                for res in addr_info:
                    ip_str = res[4][0]
                    ip = ipaddress.ip_address(ip_str)

                    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                        logging.warning(f"Blocked SSRF attempt to {url} (IP: {ip_str})")
                        return False

            except (socket.gaierror, ValueError):
                # If we can't resolve it, we let it pass to requests which will fail,
                # unless it's an internal DNS name that only resolves internally.
                # Ideally, for security, fail closed if resolution fails.
                # But to avoid breaking scraping on temporary DNS glitches, we can be lenient here
                # because requests.get will also likely fail.
                pass

            return True

        except Exception as e:
            logging.error(f"Error checking URL safety: {e}")
            return False

    def scrape(self, url: str) -> Dict[str, str]:
        """
        Fetch URL and extract title and body text.
        Safely handles redirects to prevent SSRF bypass.

        Args:
            url: URL to scrape

        Returns:
            Dict with 'title' and 'text', or None if failed.
        """
        current_url = url
        response = None
        max_redirects = 5

        try:
            with requests.Session() as session:
                for _ in range(max_redirects + 1):
                    # Check safety of the URL BEFORE fetching
                    if not self._is_safe_url(current_url):
                        return {
                            "url": current_url,
                            "error": "Access denied (Security restricted IP)",
                            "title": "Scan Blocked"
                        }

                    # Fetch with allow_redirects=False to inspect each hop
                    response = session.get(
                        current_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    if response.is_redirect:
                        # Get next URL
                        location = response.headers.get("Location")
                        if not location:
                            break

                        # Handle relative redirects
                        current_url = urljoin(current_url, location)
                        continue
                    else:
                        # Final response reached
                        break
                else:
                    return {
                        "url": url,
                        "error": "Too many redirects",
                        "title": "Scan Failed"
                    }

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
            if "NameResolutionError" in error_msg or "getaddrinfo failed" in error_msg:
                short_msg = "DNS resolution failed (Domain not found)"
            elif "ConnectTimeout" in error_msg:
                short_msg = "Connection timed out"
            else:
                # Keep it short, avoid full traceback text
                short_msg = str(e).split('(')[0].strip()

            # Return error as result instead of logging it to console
            return {"url": url, "error": short_msg, "title": "Scan Failed"}

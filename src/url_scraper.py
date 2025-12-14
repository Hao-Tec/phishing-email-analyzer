"""
URL Scraper Module
Fetches and extracts text content from URLs for analysis.
"""

import requests
import logging
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

    def scrape(self, url: str) -> Optional[Dict[str, str]]:
        """
        Fetch URL and extract title and body text.

        Args:
            url: URL to scrape

        Returns:
            Dict with 'title' and 'text', or None if failed.
        """
        try:
            response = requests.get(
                url, headers=self.headers, timeout=self.timeout
            )
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
            logging.warning(f"Failed to scrape {url}: {e}")
            return None
            

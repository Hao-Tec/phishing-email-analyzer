"""
External Scanners Module
Integrates with external phishing databases (PhishTank, Google Safe Browsing).
"""

import os
import requests
import logging
from typing import Dict

from src.config import PHISHTANK_API_KEY_ENV, SAFE_BROWSING_API_KEY_ENV


class ExternalScanners:
    """
    Checks URLs against external phishing databases.
    """

    def __init__(self):
        """Initialize scanners with API keys from environment."""
        self.phishtank_key = os.getenv(PHISHTANK_API_KEY_ENV)
        self.safebrowsing_key = os.getenv(SAFE_BROWSING_API_KEY_ENV)

    def scan_url(self, url: str) -> Dict[str, bool]:
        """
        Scan a URL against available databases.

        Args:
            url: URL to scan

        Returns:
            Dictionary with results (is_malicious: bool, details: dict)
        """
        results = {"is_malicious": False, "sources": []}

        # Check PhishTank
        if self.phishtank_key:
            if self._check_phishtank(url):
                results["is_malicious"] = True
                results["sources"].append("PhishTank")

        # Check Safe Browsing (Simplified)
        if self.safebrowsing_key and not results["is_malicious"]:
            if self._check_safebrowsing(url):
                results["is_malicious"] = True
                results["sources"].append("GoogleSafeBrowsing")

        return results

    def _check_phishtank(self, url: str) -> bool:
        """Check URL against PhishTank."""
        try:
            # Note: This is an example endpoint. Real implementation needs specific API logic.
            # Using a simplified POST request logic often used with PhishTank.
            payload = {"url": url, "format": "json", "app_key": self.phishtank_key}
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/", data=payload
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("results", {}).get("in_database", False) and data.get(
                    "results", {}
                ).get("valid", False)
        except Exception as e:
            logging.warning(f"PhishTank check failed: {e}")
        return False

    def _check_safebrowsing(self, url: str) -> bool:
        """Check URL against Google Safe Browsing."""
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safebrowsing_key}"
            payload = {
                "client": {
                    "clientId": "phishing-email-analyzer",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            response = requests.post(api_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                return bool(data.get("matches"))
        except Exception as e:
            logging.warning(f"Safe Browsing check failed: {e}")
        return False

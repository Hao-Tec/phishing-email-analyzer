"""
VirusTotal Scanner Module
Integrates with VirusTotal API to scan URLs and file hashes.
"""

import os
import hashlib
import requests
import base64
from typing import Dict


class VirusTotalScanner:
    """
    Scanner that checks URLs and file hashes against VirusTotal.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        """Initialize with API key."""
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    def scan_url(self, url: str) -> Dict:
        """
        Check a URL against VirusTotal.

        Args:
            url: The URL to check.

        Returns:
            Dictionary with scan results or error.
        """
        if not self.api_key:
            return {"error": "No API key configured"}

        try:
            # First, extract the analysis ID by submitting or just getting
            # the URL ID. VT requires base64 encoding of the URL for lookups
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            # Check if already analyzed
            response = requests.get(
                f"{self.BASE_URL}/urls/{url_id}", headers=self.headers
            )

            if response.status_code == 200:
                return self._parse_analysis(response.json())
            elif response.status_code == 404:
                # Submit the URL for scanning
                return self._submit_url(url)
            else:
                return {"error": f"API Error: {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def _submit_url(self, url: str) -> Dict:
        """
        Submit a URL to VirusTotal for scanning.

        Args:
            url: The URL to submit.

        Returns:
            Dictionary with submission status.
        """
        try:
            data = {"url": url}
            response = requests.post(
                f"{self.BASE_URL}/urls", headers=self.headers, data=data
            )

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                return {
                    "status": "queued",
                    "analysis_id": analysis_id,
                    "message": "URL submitted for scanning",
                    "harmless": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                    "reputation": 0,
                }
            else:
                # If submission fails, fall back to unknown
                return {"status": "unknown", "harmless": 0, "malicious": 0}
        except Exception:
            return {"status": "unknown", "harmless": 0, "malicious": 0}

    def scan_file_hash(self, file_content: bytes) -> Dict:
        """
        Check a file hash against VirusTotal.

        Args:
            file_content: Content of the file.

        Returns:
            Dictionary with scan results.
        """
        if not self.api_key:
            return {"error": "No API key configured"}

        sha256_hash = hashlib.sha256(file_content).hexdigest()

        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{sha256_hash}", headers=self.headers
            )

            if response.status_code == 200:
                return self._parse_analysis(response.json())
            elif response.status_code == 404:
                return {"status": "unknown", "harmless": 0, "malicious": 0}
            else:
                return {"error": f"API Error: {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def _parse_analysis(self, response_json: Dict) -> Dict:
        """Parse VT API response."""
        try:
            attributes = response_json.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "status": "completed",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation", 0),
            }
        except Exception:
            return {"error": "Failed to parse VT response"}

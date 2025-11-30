"""
Analyzer Module
Orchestrates email parsing and phishing detection.
"""

from pathlib import Path
from typing import Dict, List

from src.email_parser import EmailParser
from src.heuristics import PhishingHeuristics
from src.config import SCORE_THRESHOLD


class EmailAnalyzer:
    """
    Main analyzer that coordinates parsing and heuristics evaluation.
    """

    def __init__(self):
        """Initialize the analyzer."""
        self.parser = EmailParser()
        self.heuristics = PhishingHeuristics()

    def analyze_email(self, email_path: str) -> Dict:
        """
        Analyze a single email for phishing.

        Args:
            email_path: Path to email file

        Returns:
            Analysis results dictionary
        """
        # Parse email
        try:
            email_data = self.parser.parse_email(email_path)
        except Exception as e:
            return {"status": "error", "error": str(e), "file": email_path}

        # Evaluate with heuristics
        score, findings = self.heuristics.evaluate(email_data)

        # Determine risk level
        risk_level = self._determine_risk_level(score)

        return {
            "status": "success",
            "file": email_path,
            "email_metadata": {
                "sender": email_data.get("sender", ""),
                "recipient": email_data.get("recipient", ""),
                "subject": email_data.get("subject", ""),
                "date": email_data.get("date", ""),
                "is_html": email_data.get("is_html", False),
            },
            "phishing_suspicion_score": score,
            "risk_level": risk_level,
            "findings": findings,
            "urls_detected": len(email_data.get("urls", [])),
            "attachments_detected": len(email_data.get("attachments", [])),
            "extracted_data": {
                "urls": email_data.get("urls", []),
                "attachments": email_data.get("attachments", []),
            },
        }

    def analyze_email_from_string(self, email_string: str) -> Dict:
        """
        Analyze email from string content.

        Args:
            email_string: Email content as string

        Returns:
            Analysis results dictionary
        """
        # Parse email
        try:
            email_data = self.parser.parse_email_from_string(email_string)
        except Exception as e:
            return {"status": "error", "error": str(e)}

        # Evaluate with heuristics
        score, findings = self.heuristics.evaluate(email_data)

        # Determine risk level
        risk_level = self._determine_risk_level(score)

        return {
            "status": "success",
            "email_metadata": {
                "sender": email_data.get("sender", ""),
                "recipient": email_data.get("recipient", ""),
                "subject": email_data.get("subject", ""),
                "date": email_data.get("date", ""),
                "is_html": email_data.get("is_html", False),
            },
            "phishing_suspicion_score": score,
            "risk_level": risk_level,
            "findings": findings,
            "urls_detected": len(email_data.get("urls", [])),
            "attachments_detected": len(email_data.get("attachments", [])),
            "extracted_data": {
                "urls": email_data.get("urls", []),
                "attachments": email_data.get("attachments", []),
            },
        }

    def analyze_batch(self, email_folder: str) -> List[Dict]:
        """
        Analyze all email files in a folder.

        Args:
            email_folder: Path to folder containing email files

        Returns:
            List of analysis results
        """
        folder_path = Path(email_folder)

        if not folder_path.is_dir():
            raise ValueError(f"Invalid folder path: {email_folder}")

        results = []
        email_extensions = {".eml", ".txt", ".msg"}

        for email_file in folder_path.iterdir():
            if (
                email_file.is_file()
                and email_file.suffix.lower() in email_extensions
            ):
                result = self.analyze_email(str(email_file))
                results.append(result)

        return results

    def _determine_risk_level(self, score: float) -> str:
        """
        Determine risk level based on score.

        Args:
            score: Phishing suspicion score (0-100)

        Returns:
            Risk level string
        """
        if score < SCORE_THRESHOLD["LOW_RISK"]:
            return "SAFE"
        elif score < SCORE_THRESHOLD["MEDIUM_RISK"]:
            return "LOW_RISK"
        elif score < SCORE_THRESHOLD["HIGH_RISK"]:
            return "MEDIUM_RISK"
        elif score < SCORE_THRESHOLD["CRITICAL"]:
            return "HIGH_RISK"
        else:
            return "CRITICAL"

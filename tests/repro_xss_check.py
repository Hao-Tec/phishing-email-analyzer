# flake8: noqa: E402
"""Test for XSS vulnerability check in HTML report generation."""
import unittest
import sys
import os
import html

# Ensure src is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.reporter import EmailReporter


class TestXSS(unittest.TestCase):
    """Test XSS protection in HTML reports."""

    def test_xss_in_finding(self):
        """Test that malicious content is escaped."""
        malicious_filename = "<img src=x onerror=alert(1)>.exe"
        analysis_result = {
            "email_metadata": {},
            "phishing_suspicion_score": 100,
            "risk_level": "CRITICAL",
            "findings": [
                {
                    "heuristic": "suspicious_attachment",
                    "severity": "HIGH",
                    "description": (
                        f"Suspicious attachment extension: {malicious_filename}"
                    ),
                    "details": {"filename": malicious_filename, "other": "safe"},
                }
            ],
            "extracted_data": {},
        }

        # This call will fail if import is missing
        html_report = EmailReporter.generate_html_report(analysis_result)

        escaped_filename = html.escape(malicious_filename)

        # Verify fix
        self.assertNotIn(
            malicious_filename,
            html_report,
            "Raw malicious payload found! XSS Vulnerability detected.",
        )
        self.assertIn(
            escaped_filename, html_report, "Escaped payload not found in report!"
        )


if __name__ == "__main__":
    unittest.main()

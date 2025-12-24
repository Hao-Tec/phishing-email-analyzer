import unittest
import sys
import os
import html

# Ensure src is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.reporter import EmailReporter

class TestXSS(unittest.TestCase):
    def test_xss_in_finding(self):
        malicious_filename = "<img src=x onerror=alert(1)>.exe"
        analysis_result = {
            "email_metadata": {},
            "phishing_suspicion_score": 100,
            "risk_level": "CRITICAL",
            "findings": [
                {
                    "heuristic": "suspicious_attachment",
                    "severity": "HIGH",
                    "description": f"Suspicious attachment extension: {malicious_filename}",
                    "details": {
                        "filename": malicious_filename,
                        "other": "safe"
                    }
                }
            ],
            "extracted_data": {}
        }

        html_report = EmailReporter.generate_html_report(analysis_result)

        escaped_filename = html.escape(malicious_filename)

        # We expect the HTML to contain the ESCAPED version, not the raw version.
        # This will FAIL if the code is vulnerable (XSS present)
        self.assertNotIn(malicious_filename, html_report, "Raw malicious payload found in report! XSS Vulnerability detected.")
        self.assertIn(escaped_filename, html_report, "Escaped payload not found in report!")

if __name__ == '__main__':
    unittest.main()

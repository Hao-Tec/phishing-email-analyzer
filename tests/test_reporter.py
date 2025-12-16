
import unittest
from src.reporter import EmailReporter


class TestEmailReporter(unittest.TestCase):
    def test_generate_html_report_sorting(self):
        """Test that findings are sorted by severity in the HTML report."""
        analysis_result = {
            "email_metadata": {},
            "phishing_suspicion_score": 80,
            "risk_level": "HIGH_RISK",
            "findings": [
                {"severity": "LOW", "heuristic": "low_issue",
                 "description": "low"},
                {"severity": "HIGH", "heuristic": "high_issue",
                 "description": "high"},
                {"severity": "MEDIUM", "heuristic": "medium_issue",
                 "description": "medium"},
            ]
        }

        html = EmailReporter.generate_html_report(analysis_result)

        # We expect HIGH to come before MEDIUM, which comes before LOW
        high_index = html.find("high_issue")
        medium_index = html.find("medium_issue")
        low_index = html.find("low_issue")

        # Check if they exist
        self.assertNotEqual(high_index, -1, "High finding not found")
        self.assertNotEqual(medium_index, -1, "Medium finding not found")
        self.assertNotEqual(low_index, -1, "Low finding not found")

        # Check order
        self.assertLess(
            high_index, medium_index, "High should be before Medium"
        )
        self.assertLess(
            medium_index, low_index, "Medium should be before Low"
        )

    def test_generate_html_report_unknown_severity(self):
        """Test that unknown severity findings are still included."""
        analysis_result = {
            "email_metadata": {},
            "phishing_suspicion_score": 50,
            "risk_level": "MEDIUM_RISK",
            "findings": [
                {"severity": "UNKNOWN_TYPE", "heuristic": "weird_issue",
                 "description": "weird"},
                {"severity": "HIGH", "heuristic": "high_issue",
                 "description": "high"},
            ]
        }

        html = EmailReporter.generate_html_report(analysis_result)

        # High should come first (known severity)
        high_index = html.find("high_issue")
        unknown_index = html.find("weird_issue")

        self.assertNotEqual(high_index, -1, "High finding not found")
        self.assertNotEqual(unknown_index, -1, "Unknown finding not found")

        # Known severity should come before unknown (appended at end)
        self.assertLess(
            high_index, unknown_index, "High should be before Unknown"
        )


if __name__ == "__main__":
    unittest.main()

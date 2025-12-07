import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analyzer import EmailAnalyzer  # noqa: E402
from src.auth_validator import AuthValidator, DKIM_AVAILABLE  # noqa: E402
from src.image_analyzer import ImageAnalyzer  # noqa: E402
from src.ml_analyzer import MLAnalyzer  # noqa: E402
from src.external_scanners import ExternalScanners  # noqa: E402


class TestEnhancements(unittest.TestCase):

    def setUp(self):
        self.analyzer = EmailAnalyzer()

    def test_components_initialization(self):
        """Test that all new components are initialized in the analyzer."""
        self.assertIsInstance(self.analyzer.auth_validator, AuthValidator)
        self.assertIsInstance(self.analyzer.image_analyzer, ImageAnalyzer)
        self.assertIsInstance(self.analyzer.ml_analyzer, MLAnalyzer)
        self.assertIsInstance(self.analyzer.external_scanners, ExternalScanners)

    def test_auth_validator(self):
        """Test AuthValidator logic."""
        if not DKIM_AVAILABLE:
            print("Skipping DKIM test - library not installed")
            return

        with patch("src.auth_validator.dkim.verify") as mock_dkim, patch(
            "src.auth_validator.AuthValidator._get_dns_record"
        ) as mock_dns:

            # Mock DKIM pass
            mock_dkim.return_value = True
            # Mock SPF record
            mock_dns.return_value = ["v=spf1 include:_spf.google.com ~all"]

            validator = AuthValidator()
            results = validator.validate(b"raw email content", {}, "test@example.com")

            self.assertTrue(results["dkim_pass"])

    @patch("src.external_scanners.requests.post")
    def test_external_scanner(self, mock_post):
        """Test External Scanner with mocked API response."""
        # Mock positive phishing result
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {"in_database": True, "valid": True},
            "matches": [{"threatType": "MALWARE"}],
        }
        mock_post.return_value = mock_response

        # Enable a key for testing
        scanner = ExternalScanners()
        scanner.phishtank_key = "dummy"

        res = scanner.scan_url("http://evil.com")
        self.assertTrue(res["is_malicious"])
        self.assertIn("PhishTank", res["sources"])

    def test_analyzer_integration(self):
        """Test that analyze_email_from_string runs without crashing including
        new components."""
        # This will use real components where possible (e.g. ML might be
        # disabled if no model)
        email_content = """From: user@example.com
To: victim@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

Please verify your account at http://suspicious-link.com
"""
        result = self.analyzer.analyze_email_from_string(email_content)

        self.assertEqual(result["status"], "success")
        self.assertIn("phishing_suspicion_score", result)


if __name__ == "__main__":
    unittest.main()

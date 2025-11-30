"""
Unit tests for Email Phishing Detection Tool
"""

import sys
import unittest
from pathlib import Path

from src.analyzer import EmailAnalyzer
from src.email_parser import EmailParser
from src.heuristics import PhishingHeuristics

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestEmailParser(unittest.TestCase):
    """Test cases for email parser module."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = EmailParser()

    def test_parse_valid_eml(self):
        """Test parsing a valid EML file."""
        sample_file = (
            Path(__file__).parent.parent / "samples" / "legitimate_email_1.eml"
        )
        if sample_file.exists():
            result = self.parser.parse_email(str(sample_file))
            self.assertIn("sender", result)
            self.assertIn("subject", result)
            self.assertTrue(len(result.get("sender", "")) > 0)

    def test_extract_sender(self):
        """Test sender extraction."""
        email_string = """From: John Doe <john@example.com>
To: recipient@example.com
Subject: Test
Date: Fri, 29 Nov 2024 10:00:00 +0000

Test body"""
        result = self.parser.parse_email_from_string(email_string)
        self.assertEqual(result["sender"].lower(), "john@example.com")

    def test_extract_urls(self):
        """Test URL extraction."""
        email_string = """From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Fri, 29 Nov 2024 10:00:00 +0000
Content-Type: text/html

<html>
<body>
Visit <a href="https://example.com">Example</a>
Or https://another.com
</body>
</html>"""
        result = self.parser.parse_email_from_string(email_string)
        urls = result["urls"]
        self.assertGreater(len(urls), 0)


class TestPhishingHeuristics(unittest.TestCase):
    """Test cases for phishing heuristics module."""

    def setUp(self):
        """Set up test fixtures."""
        self.heuristics = PhishingHeuristics()

    def test_suspicious_domain_detection(self):
        """Test detection of suspicious domains."""
        email_data = {
            "sender": "support@bank-777.tk",
            "recipient": "user@example.com",
            "subject": "Verify Account",
            "date": "Fri, 29 Nov 2024 10:00:00",
            "headers": {},
            "body": "",
            "urls": [],
            "attachments": [],
            "is_html": False,
            "reply_to": "",
        }
        score, findings = self.heuristics.evaluate(email_data)
        self.assertGreater(score, 0)

    def test_url_obfuscation_detection(self):
        """Test detection of URL obfuscation."""
        email_data = {
            "sender": "legitimate@example.com",
            "recipient": "user@example.com",
            "subject": "Test",
            "date": "Fri, 29 Nov 2024 10:00:00",
            "headers": {},
            "body": "",
            "urls": [
                {
                    "url": "https://bit.ly/shorturl",
                    "domain": "bit.ly",
                    "scheme": "https",
                    "path": "",
                }
            ],
            "attachments": [],
            "is_html": False,
            "reply_to": "",
        }
        score, findings = self.heuristics.evaluate(email_data)
        # Should detect shortened URL
        self.assertGreater(score, 0)

    def test_suspicious_attachment_detection(self):
        """Test detection of suspicious attachments."""
        email_data = {
            "sender": "sender@example.com",
            "recipient": "user@example.com",
            "subject": "Test",
            "date": "Fri, 29 Nov 2024 10:00:00",
            "headers": {},
            "body": "",
            "urls": [],
            "attachments": [
                {
                    "filename": "invoice.exe",
                    "size": 1024,
                    "content_type": "application/octet-stream",
                }
            ],
            "is_html": False,
            "reply_to": "",
        }
        score, findings = self.heuristics.evaluate(email_data)
        self.assertGreater(score, 0)


class TestEmailAnalyzer(unittest.TestCase):
    """Test cases for email analyzer module."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = EmailAnalyzer()

    def test_analyze_sample_emails(self):
        """Test analyzing sample emails."""
        samples_dir = Path(__file__).parent.parent / "samples"

        if samples_dir.exists():
            for email_file in samples_dir.glob("*.eml"):
                result = self.analyzer.analyze_email(str(email_file))
                self.assertIn("status", result)
                if result["status"] == "success":
                    self.assertIn("phishing_suspicion_score", result)
                    self.assertIn("risk_level", result)
                    self.assertIn("findings", result)

    def test_risk_level_determination(self):
        """Test risk level determination based on score."""
        # Create simple email data
        email_data = {
            "sender": "safe@example.com",
            "recipient": "user@example.com",
            "subject": "Normal Email",
            "date": "Fri, 29 Nov 2024 10:00:00",
            "headers": {},
            "body": "This is a normal email.",
            "urls": [],
            "attachments": [],
            "is_html": False,
            "reply_to": "",
        }

        heuristics = PhishingHeuristics()
        score, findings = heuristics.evaluate(email_data)
        risk_level = self.analyzer._determine_risk_level(score)

        # Safe email should have low risk
        self.assertIn(risk_level, ["SAFE", "LOW_RISK"])


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def test_full_pipeline(self):
        """Test the full analysis pipeline."""
        parser = EmailParser()
        heuristics = PhishingHeuristics()

        email_string = """From: attacker@phishing.tk
To: victim@example.com
Subject: URGENT: Verify Your Account NOW!!!
Date: Fri, 29 Nov 2024 10:00:00 +0000
Content-Type: text/html

<html>
<body>
<a href="http://192.168.1.1/login">Click here to verify</a>
</body>
</html>"""

        # Parse
        email_data = parser.parse_email_from_string(email_string)

        # Analyze
        score, findings = heuristics.evaluate(email_data)

        # Check results
        self.assertGreater(score, 0)
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()

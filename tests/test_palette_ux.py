
import unittest
from src.reporter import EmailReporter

class TestPaletteUX(unittest.TestCase):
    def test_copy_button_and_accessibility(self):
        """Test that the HTML report includes the Copy URL button and accessibility enhancements."""
        analysis_result = {
            "email_metadata": {
                "sender": "test@example.com",
                "recipient": "victim@example.com",
                "subject": "Test Email",
                "date": "2023-10-27"
            },
            "phishing_suspicion_score": 10,
            "risk_level": "LOW_RISK",
            "findings": [],
            "extracted_data": {
                "urls": [
                    {
                        "url": "http://evil.com/login?u=1&p=2",
                        "domain": "evil.com",
                        "displayed_text": "Click Here"
                    },
                    {
                        "url": "https://safe.com/'quote'",
                        "domain": "safe.com"
                    }
                ],
                "attachments": []
            }
        }

        html = EmailReporter.generate_html_report(analysis_result)

        # 1. Check for CSS class
        self.assertIn(".copy-btn {", html, "CSS for copy-btn should be present")

        # 2. Check for JS function
        self.assertIn("function copyToClipboard(btn)", html, "JS copyToClipboard function should be present")

        # 3. Check for Button existence
        self.assertIn("<button class='copy-btn'", html, "Copy button should be present")

        # 4. Check for data-url attribute
        # We need to check if the URL is correctly placed in data-url
        # The URL 'http://evil.com/login?u=1&p=2' becomes 'http://evil.com/login?u=1&amp;p=2' when escaped
        # but in data-url it should be properly quoted.
        # Let's check for the substring presence.
        self.assertIn("data-url='http://evil.com/login?u=1&amp;p=2'", html, "data-url should contain the escaped URL")

        # Check the quote handling
        # 'https://safe.com/'quote'' -> escaped: 'https://safe.com/&#x27;quote&#x27;'
        self.assertIn("data-url='https://safe.com/&#x27;quote&#x27;'", html, "data-url should handle quotes correctly")

        # 5. Check for aria-label on the link
        self.assertIn("aria-label='https://safe.com/&#x27;quote&#x27; (opens in new tab)'", html, "Link should have aria-label")

if __name__ == "__main__":
    unittest.main()

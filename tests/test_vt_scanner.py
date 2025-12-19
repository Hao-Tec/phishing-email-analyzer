import unittest
from unittest.mock import patch, MagicMock
import base64
import os
from src.vt_scanner import VirusTotalScanner


class TestVirusTotalScanner(unittest.TestCase):
    def setUp(self):
        self.api_key = "dummy_api_key"
        self.headers = {
            "x-apikey": self.api_key,
            "User-Agent": "phishing-email-analyzer/1.0"
        }
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": self.api_key}):
            self.scanner = VirusTotalScanner()

    @patch("src.vt_scanner.requests.get")
    def test_scan_url_existing(self, mock_get):
        """Test scan_url when URL exists in VT."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "harmless": 80,
                        "undetected": 0
                    },
                    "reputation": -10
                }
            }
        }
        mock_get.return_value = mock_response

        url = "http://malicious.com"
        result = self.scanner.scan_url(url)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["malicious"], 5)

        # Verify call
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        expected_url = (
            f"https://www.virustotal.com/api/v3/urls/{url_id}"
        )
        mock_get.assert_called_with(
            expected_url, headers=self.headers, timeout=15
        )

    @patch("src.vt_scanner.requests.post")
    @patch("src.vt_scanner.requests.get")
    def test_scan_url_unknown_submit(self, mock_get, mock_post):
        """Test scan_url when URL is unknown (404) and triggers submission."""
        # Mock GET returning 404
        mock_get_response = MagicMock()
        mock_get_response.status_code = 404
        mock_get.return_value = mock_get_response

        # Mock POST returning 200 (queued)
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            "data": {
                "id": "analysis_id_123"
            }
        }
        mock_post.return_value = mock_post_response

        url = "http://unknown.com"
        result = self.scanner.scan_url(url)

        # Expect submission
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://www.virustotal.com/api/v3/urls")
        self.assertEqual(kwargs["data"]["url"], url)
        self.assertEqual(kwargs["headers"], self.headers)
        self.assertEqual(kwargs["timeout"], 15)

        # Check result
        self.assertEqual(result["status"], "queued")
        self.assertEqual(result["analysis_id"], "analysis_id_123")

    @patch("src.vt_scanner.requests.post")
    @patch("src.vt_scanner.requests.get")
    def test_scan_url_unknown_submit_fail(self, mock_get, mock_post):
        """Test scan_url when URL is unknown (404) and submission fails."""
        # Mock GET returning 404
        mock_get_response = MagicMock()
        mock_get_response.status_code = 404
        mock_get.return_value = mock_get_response

        # Mock POST returning 500
        mock_post_response = MagicMock()
        mock_post_response.status_code = 500
        mock_post.return_value = mock_post_response

        url = "http://unknown.com"
        result = self.scanner.scan_url(url)

        # Expect submission attempted
        mock_post.assert_called_once()

        # Check result fallback
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["malicious"], 0)


if __name__ == "__main__":
    unittest.main()

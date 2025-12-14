import unittest
from unittest.mock import patch, MagicMock
from src.external_scanners import ExternalScanners


class TestExternalScanners(unittest.TestCase):
    def setUp(self):
        self.scanners = ExternalScanners()

    @patch("src.external_scanners.requests.post")
    def test_check_phishtank_valid_phish(self, mock_post):
        """Test PhishTank check with a valid phishing URL."""
        # Mock response for a phishing URL
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {"in_database": True, "valid": True}
        }
        mock_post.return_value = mock_response

        url = "http://phishing-site.com"
        result = self.scanners._check_phishtank(url)

        self.assertTrue(result)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://checkurl.phishtank.com/checkurl/")
        self.assertEqual(kwargs["data"]["url"], url)
        # We will verify User-Agent after we implement it

    @patch("src.external_scanners.requests.post")
    def test_check_phishtank_not_phish(self, mock_post):
        """Test PhishTank check with a non-phishing URL."""
        # Mock response for a safe URL
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {"in_database": False, "valid": False}
        }
        mock_post.return_value = mock_response

        url = "http://google.com"
        result = self.scanners._check_phishtank(url)

        self.assertFalse(result)

    @patch("src.external_scanners.requests.post")
    def test_check_phishtank_error(self, mock_post):
        """Test PhishTank check with an error."""
        mock_post.side_effect = Exception("Network error")

        url = "http://google.com"
        result = self.scanners._check_phishtank(url)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch, MagicMock
from src.url_scraper import URLScraper
import socket

class TestSSRFProtection(unittest.TestCase):
    def setUp(self):
        self.scraper = URLScraper()

    @patch('src.url_scraper.socket.gethostbyname')
    def test_block_private_ip(self, mock_gethostbyname):
        """Test that private IPs are blocked."""
        # Mock DNS resolution to a private IP
        mock_gethostbyname.return_value = '192.168.1.1'

        result = self.scraper.scrape("http://internal-server.local")

        self.assertEqual(result['title'], "Security Block")
        self.assertIn("Access denied", result['error'])
        mock_gethostbyname.assert_called_with('internal-server.local')

    @patch('src.url_scraper.socket.gethostbyname')
    def test_block_localhost(self, mock_gethostbyname):
        """Test that localhost is blocked."""
        mock_gethostbyname.return_value = '127.0.0.1'

        result = self.scraper.scrape("http://localhost:8080")

        self.assertEqual(result['title'], "Security Block")
        self.assertIn("Access denied", result['error'])

    @patch('src.url_scraper.socket.gethostbyname')
    @patch('src.url_scraper.requests.get')
    def test_allow_public_ip(self, mock_get, mock_gethostbyname):
        """Test that public IPs are allowed."""
        mock_gethostbyname.return_value = '93.184.216.34' # example.com

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><title>Example Domain</title><body><h1>Example Domain</h1></body></html>"
        mock_response.is_redirect = False
        mock_response.iter_content.return_value = [b"<html><title>Example Domain</title><body><h1>Example Domain</h1></body></html>"]

        mock_get.return_value = mock_response

        result = self.scraper.scrape("http://example.com")

        self.assertEqual(result['title'], "Example Domain")
        self.assertIn("Example Domain", result['text'])
        mock_get.assert_called()

    @patch('src.url_scraper.socket.gethostbyname')
    @patch('src.url_scraper.requests.get')
    def test_redirect_to_private_ip_blocked(self, mock_get, mock_gethostbyname):
        """Test that a redirect to a private IP is blocked."""

        # First call resolves safe IP, second call resolves private IP
        def side_effect(hostname):
            if hostname == "safe.com":
                return "1.2.3.4"
            elif hostname == "evil.internal":
                return "10.0.0.1"
            return "0.0.0.0"

        mock_gethostbyname.side_effect = side_effect

        # Setup redirect response
        redirect_response = MagicMock()
        redirect_response.status_code = 302
        redirect_response.is_redirect = True
        redirect_response.headers = {'Location': 'http://evil.internal/admin'}

        mock_get.return_value = redirect_response

        result = self.scraper.scrape("http://safe.com")

        # It should process the first URL, see the redirect, check the new URL, and block it
        self.assertEqual(result['title'], "Security Block")
        self.assertIn("Access denied", result['error'])

        # Verify requests.get was called with allow_redirects=False
        args, kwargs = mock_get.call_args
        self.assertFalse(kwargs['allow_redirects'])

if __name__ == '__main__':
    unittest.main()

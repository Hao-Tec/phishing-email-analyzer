import unittest
from unittest.mock import patch, MagicMock
from src.url_scraper import URLScraper
import socket

class TestSSRFProtection(unittest.TestCase):
    def setUp(self):
        self.scraper = URLScraper()

    @patch('src.url_scraper.socket.gethostbyname')
    def test_block_private_ip(self, mock_gethostbyname):
        # Mock DNS to return a private IP
        mock_gethostbyname.return_value = '192.168.1.1'

        result = self.scraper.scrape("http://internal-dashboard.local")

        self.assertEqual(result.get('error'), "Blocked: Potential SSRF")
        self.assertEqual(result.get('title'), "Security Alert")

    @patch('src.url_scraper.socket.gethostbyname')
    def test_block_loopback_ip(self, mock_gethostbyname):
        # Mock DNS to return loopback
        mock_gethostbyname.return_value = '127.0.0.1'

        result = self.scraper.scrape("http://localhost:8080")

        self.assertEqual(result.get('error'), "Blocked: Potential SSRF")

    @patch('src.url_scraper.socket.gethostbyname')
    @patch('src.url_scraper.requests.Session')
    def test_allow_public_ip(self, mock_session, mock_gethostbyname):
        # Mock DNS to return a public IP
        mock_gethostbyname.return_value = '8.8.8.8'

        # Mock successful request
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><title>Google</title><body>Search</body></html>"
        mock_response.is_redirect = False

        mock_session_instance = mock_session.return_value
        mock_session_instance.get.return_value = mock_response

        result = self.scraper.scrape("http://google.com")

        self.assertEqual(result.get('title'), "Google")
        self.assertNotIn('error', result)

    @patch('src.url_scraper.socket.gethostbyname')
    @patch('src.url_scraper.requests.Session')
    def test_block_redirect_to_private_ip(self, mock_session, mock_gethostbyname):
        # Setup side effects for DNS resolution
        # First call: valid public IP (for initial URL)
        # Second call: private IP (for redirected URL)
        def gethostbyname_side_effect(hostname):
            if hostname == "safe.com":
                return "8.8.8.8"
            elif hostname == "evil.internal":
                return "10.0.0.1"
            return "0.0.0.0" # Fallback

        mock_gethostbyname.side_effect = gethostbyname_side_effect

        mock_session_instance = mock_session.return_value

        # First response is a redirect
        redirect_response = MagicMock()
        redirect_response.is_redirect = True
        redirect_response.headers = {'Location': 'http://evil.internal/secret'}
        redirect_response.status_code = 302

        # Configure get to return redirect first
        mock_session_instance.get.side_effect = [redirect_response]

        result = self.scraper.scrape("http://safe.com")

        self.assertEqual(result.get('error'), "Blocked: Potential SSRF")

if __name__ == '__main__':
    unittest.main()

import unittest
from unittest.mock import patch, MagicMock
from src.url_scraper import URLScraper
import socket

class TestSSRFProtection(unittest.TestCase):
    def setUp(self):
        self.scraper = URLScraper()

    @patch('src.url_scraper.requests.Session')
    @patch('src.url_scraper.socket.gethostbyname')
    def test_public_ip(self, mock_gethostbyname, mock_session_cls):
        # Setup mock for public IP
        mock_gethostbyname.return_value = '8.8.8.8'

        # Setup mock session and response
        mock_session = mock_session_cls.return_value
        mock_response = MagicMock()
        mock_response.content = b"<html><title>Safe content</title><body>Safe content</body></html>"
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '100'}
        mock_response.is_redirect = False
        # Mock iter_content for the new stream=True logic
        mock_response.iter_content.return_value = [b"<html><title>Safe content</title><body>Safe content</body></html>"]

        mock_session.get.return_value = mock_response

        result = self.scraper.scrape("http://example.com")
        self.assertNotIn("error", result)
        self.assertEqual(result["title"], "Safe content")

    @patch('src.url_scraper.socket.gethostbyname')
    def test_private_ip_loopback(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '127.0.0.1'
        result = self.scraper.scrape("http://localhost")
        self.assertIn("error", result)
        self.assertIn("blocked", result.get("error", "").lower())

    @patch('src.url_scraper.socket.gethostbyname')
    def test_private_ip_rfc1918(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '192.168.1.1'
        result = self.scraper.scrape("http://router.local")
        self.assertIn("error", result)
        self.assertIn("blocked", result.get("error", "").lower())

    @patch('src.url_scraper.socket.gethostbyname')
    def test_private_ip_aws_metadata(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '169.254.169.254'
        result = self.scraper.scrape("http://169.254.169.254")
        self.assertIn("error", result)
        self.assertIn("blocked", result.get("error", "").lower())

    @patch('src.url_scraper.requests.Session')
    @patch('src.url_scraper.socket.gethostbyname')
    def test_redirect_to_private_ip(self, mock_gethostbyname, mock_session_cls):
        # Initial URL is safe
        mock_gethostbyname.side_effect = ['8.8.8.8', '127.0.0.1'] # First call safe, second call unsafe

        mock_session = mock_session_cls.return_value

        # First response is a redirect
        mock_response1 = MagicMock()
        mock_response1.is_redirect = True
        mock_response1.headers = {'Location': 'http://malicious-internal.com'}

        # We don't need a second response because it should block before making the request

        mock_session.get.side_effect = [mock_response1]

        result = self.scraper.scrape("http://example.com")
        self.assertIn("error", result)
        self.assertIn("blocked", result.get("error", "").lower())

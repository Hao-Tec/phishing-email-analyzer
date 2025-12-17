import unittest
from unittest.mock import patch, MagicMock
from src.url_scraper import URLScraper
import socket

class TestSSRFProtection(unittest.TestCase):
    def setUp(self):
        self.scraper = URLScraper()

    @patch('socket.getaddrinfo')
    def test_block_private_ip(self, mock_getaddrinfo):
        # Mock DNS resolution to a private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80))
        ]

        result = self.scraper.scrape("http://internal-service.com")
        self.assertIn("error", result)
        self.assertIn("SSRF", result["error"])

    @patch('socket.getaddrinfo')
    def test_block_loopback_ip(self, mock_getaddrinfo):
        # Mock DNS resolution to loopback
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))
        ]

        result = self.scraper.scrape("http://localhost")
        self.assertIn("error", result)
        self.assertIn("SSRF", result["error"])

    @patch('socket.getaddrinfo')
    def test_block_link_local_ip(self, mock_getaddrinfo):
        # Mock DNS resolution to link-local IP (Cloud Metadata)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 80))
        ]

        result = self.scraper.scrape("http://169.254.169.254")
        self.assertIn("error", result)
        self.assertIn("SSRF", result["error"])

    @patch('socket.getaddrinfo')
    @patch('requests.Session.get')
    def test_allow_public_ip(self, mock_get, mock_getaddrinfo):
        # Mock DNS resolution to a public IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))
        ]

        # Mock requests response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><head><title>Example</title></head><body>Hello World</body></html>"
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.is_redirect = False
        mock_get.return_value = mock_response

        result = self.scraper.scrape("http://example.com")

        self.assertEqual(result["title"], "Example")
        self.assertIn("Hello World", result["text"])
        self.assertNotIn("error", result)

    @patch('socket.getaddrinfo')
    @patch('requests.Session.get')
    def test_block_redirect_to_private(self, mock_get, mock_getaddrinfo):
        # Scenario:
        # 1. safe-site.com resolves to public IP
        # 2. safe-site.com redirects to internal-site.com
        # 3. internal-site.com resolves to private IP

        def side_effect_dns(host, port):
            if "safe-site.com" in host:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
            if "internal-site.com" in host:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 80))]
            return []

        mock_getaddrinfo.side_effect = side_effect_dns

        # First response is a redirect
        resp1 = MagicMock()
        resp1.is_redirect = True
        resp1.headers = {'Location': 'http://internal-site.com'}
        resp1.url = 'http://safe-site.com'

        # We shouldn't even get to the second request because validation happens first
        # But if we did, it would be blocked.

        mock_get.return_value = resp1

        result = self.scraper.scrape("http://safe-site.com")

        self.assertIn("error", result)
        self.assertIn("SSRF", result["error"])

if __name__ == '__main__':
    unittest.main()

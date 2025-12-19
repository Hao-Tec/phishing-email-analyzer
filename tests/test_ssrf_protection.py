import unittest
from unittest.mock import patch, MagicMock
from src.url_scraper import URLScraper
import socket

class TestSSRFProtection(unittest.TestCase):
    def setUp(self):
        self.scraper = URLScraper()

    @patch('src.url_scraper.socket.getaddrinfo')
    def test_ssrf_blocked_localhost(self, mock_getaddrinfo):
        """
        Test that accessing localhost is blocked.
        """
        # Mock DNS resolution to return 127.0.0.1
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        # sockaddr is (ip, port) for IPv4
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))
        ]

        url = "http://localhost/admin"

        # Should return an error dict, not raise exception (handled in scrape)
        result = self.scraper.scrape(url)

        self.assertIn("error", result)
        self.assertIn("Access denied", result["error"])

    @patch('src.url_scraper.socket.getaddrinfo')
    def test_ssrf_blocked_private_ip(self, mock_getaddrinfo):
        """
        Test that accessing private IP is blocked.
        """
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80))
        ]

        url = "http://intranet.local"
        result = self.scraper.scrape(url)

        self.assertIn("error", result)
        self.assertIn("Access denied", result["error"])

    @patch('src.url_scraper.socket.getaddrinfo')
    def test_ssrf_blocked_cloud_metadata(self, mock_getaddrinfo):
        """
        Test that accessing AWS metadata IP is blocked.
        """
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 80))
        ]

        url = "http://169.254.169.254/latest/meta-data/"
        result = self.scraper.scrape(url)

        self.assertIn("error", result)
        self.assertIn("Access denied", result["error"])

    @patch('src.url_scraper.socket.getaddrinfo')
    @patch('requests.Session')
    def test_valid_public_url(self, mock_session, mock_getaddrinfo):
        """
        Test that accessing a valid public IP is allowed.
        """
        # Mock DNS to return a public IP (e.g., Google's 8.8.8.8)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 80))
        ]

        # Mock the session and response
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.headers = {'content-length': '100'}
        mock_response.iter_content.return_value = [b"<html><body>Public Content</body></html>"]
        mock_response.content = b"<html><body>Public Content</body></html>" # Fallback if needed

        mock_inst = mock_session.return_value.__enter__.return_value
        mock_inst.get.return_value = mock_response

        url = "http://google.com"
        result = self.scraper.scrape(url)

        # Should succeed
        self.assertNotIn("error", result)
        self.assertIn("Public Content", result["text"])

    @patch('src.url_scraper.socket.getaddrinfo')
    @patch('requests.Session')
    def test_ssrf_via_redirect(self, mock_session, mock_getaddrinfo):
        """
        Test that redirection to a private IP is blocked.
        """
        # We need side_effect for getaddrinfo to handle different hostnames
        def getaddrinfo_side_effect(host, port):
            if host == "evil.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 80))]
            elif host == "localhost":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('0.0.0.0', 0))]

        mock_getaddrinfo.side_effect = getaddrinfo_side_effect

        # Mock response 1: Redirect
        response1 = MagicMock()
        response1.is_redirect = True
        response1.headers = {'Location': 'http://localhost/secret'}

        # Mock response 2: Should not be reached if blocked, but just in case
        response2 = MagicMock()

        mock_inst = mock_session.return_value.__enter__.return_value
        mock_inst.get.side_effect = [response1, response2]

        url = "http://evil.com/redirect"
        result = self.scraper.scrape(url)

        self.assertIn("error", result)
        self.assertIn("Access denied", result["error"])

if __name__ == '__main__':
    unittest.main()

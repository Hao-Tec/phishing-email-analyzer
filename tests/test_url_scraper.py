import unittest
from unittest.mock import patch
from src.url_scraper import URLScraper

class TestURLScraperSSRF(unittest.TestCase):
    def setUp(self):
        self.scraper = URLScraper()

    @patch('socket.getaddrinfo')
    def test_scrape_blocks_loopback_ip(self, mock_getaddrinfo):
        # Simulate DNS resolving to localhost
        # socket.getaddrinfo return format: [(family, type, proto, canonname, sockaddr)]
        mock_getaddrinfo.return_value = [(2, 1, 6, '', ('127.0.0.1', 80))]

        with patch('requests.get') as mock_get:
            result = self.scraper.scrape("http://malicious-local.com")

            # Expectation: Request should be blocked, so requests.get is NOT called
            mock_get.assert_not_called()
            self.assertIn('error', result)
            self.assertIn('Security check failed', result['error'])

    @patch('socket.getaddrinfo')
    def test_scrape_blocks_private_ip(self, mock_getaddrinfo):
        # Simulate DNS resolving to a private IP
        mock_getaddrinfo.return_value = [(2, 1, 6, '', ('192.168.1.1', 80))]

        with patch('requests.get') as mock_get:
            result = self.scraper.scrape("http://intranet.local")

            mock_get.assert_not_called()
            self.assertIn('error', result)
            self.assertIn('Security check failed', result['error'])

    @patch('socket.getaddrinfo')
    def test_scrape_blocks_link_local_ip(self, mock_getaddrinfo):
        # 169.254.x.x (AWS metadata, etc)
        mock_getaddrinfo.return_value = [(2, 1, 6, '', ('169.254.169.254', 80))]

        with patch('requests.get') as mock_get:
            result = self.scraper.scrape("http://metadata.local")

            mock_get.assert_not_called()
            self.assertIn('error', result)

    @patch('socket.getaddrinfo')
    def test_scrape_allows_public_ip(self, mock_getaddrinfo):
        # Public IP (e.g., Google DNS)
        # The mock needs to be dynamic because scrape() might call getaddrinfo multiple times
        # for redirects (though here we test the happy path without redirects first)
        mock_getaddrinfo.return_value = [(2, 1, 6, '', ('8.8.8.8', 80))]

        # We need to mock the response of requests.get since it WILL be called
        with patch('requests.get') as mock_get:
            mock_response = unittest.mock.Mock()
            # Must simulate bs4 parsing
            mock_response.content = b"<html><title>Hello</title><body>Hello World</body></html>"
            mock_response.status_code = 200
            mock_response.is_redirect = False # Important for our manual redirect loop
            mock_get.return_value = mock_response

            result = self.scraper.scrape("http://google.com")

            mock_get.assert_called()
            self.assertEqual(result['title'], "Hello")
            self.assertIn("Hello World", result['text'])

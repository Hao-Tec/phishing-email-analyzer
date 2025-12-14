
import unittest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.url_scraper import URLScraper

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestURLScraperSSRF(unittest.TestCase):
    """Test cases for SSRF protection in URLScraper."""

    def setUp(self):
        self.scraper = URLScraper()

    def test_block_localhost(self):
        """Test blocking localhost access."""
        url = "http://localhost:8080"
        result = self.scraper.scrape(url)
        self.assertIn("error", result)
        self.assertIn("Security restricted IP", result["error"])

    def test_block_loopback_ip(self):
        """Test blocking loopback IP 127.0.0.1."""
        url = "http://127.0.0.1:8080"
        result = self.scraper.scrape(url)
        self.assertIn("error", result)
        self.assertIn("Security restricted IP", result["error"])

    def test_block_private_ip(self):
        """Test blocking private IP range 192.168.x.x."""
        url = "http://192.168.1.1"
        result = self.scraper.scrape(url)
        self.assertIn("error", result)
        self.assertIn("Security restricted IP", result["error"])

    def test_block_private_ip_10(self):
        """Test blocking private IP range 10.x.x.x."""
        url = "http://10.0.0.5"
        result = self.scraper.scrape(url)
        self.assertIn("error", result)
        self.assertIn("Security restricted IP", result["error"])

    @patch('src.url_scraper.socket.getaddrinfo')
    def test_allow_public_ip(self, mock_getaddrinfo):
        """Test allowing a public IP."""
        # Mock getaddrinfo to return a safe public IP (8.8.8.8)
        # Structure of getaddrinfo return: list of (family, type, proto, canonname, sockaddr)
        # sockaddr for IPv4 is (address, port)
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('8.8.8.8', 80))
        ]

        # We also need to mock requests.get so we don't actually hit the network
        with patch('requests.Session.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = b"<html><title>Safe</title><body>Hello World</body></html>"
            mock_response.is_redirect = False
            mock_get.return_value = mock_response

            result = self.scraper.scrape("http://example.com")

            self.assertEqual(result["title"], "Safe")
            # BeautifulSoup.get_text() includes title text if inside html
            self.assertIn("Hello World", result["text"])
            self.assertNotIn("error", result)

    def test_is_safe_url(self):
        """Directly test _is_safe_url method."""
        # Unsafe
        self.assertFalse(self.scraper._is_safe_url("http://localhost"))
        self.assertFalse(self.scraper._is_safe_url("http://127.0.0.1"))
        self.assertFalse(self.scraper._is_safe_url("http://192.168.0.1"))
        self.assertFalse(self.scraper._is_safe_url("http://10.10.10.10"))

        # Test Safe with Mock
        with patch('src.url_scraper.socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(2, 1, 6, '', ('8.8.8.8', 80))]
            self.assertTrue(self.scraper._is_safe_url("http://google.com"))

    @patch('src.url_scraper.socket.getaddrinfo')
    def test_redirect_to_unsafe(self, mock_getaddrinfo):
        """Test that redirecting to an unsafe URL is blocked."""
        # Setup mock to return safe IP for first call, then unsafe IP for second call
        # Side_effect allows returning different values for consecutive calls
        def getaddrinfo_side_effect(host, port):
            if "safe.com" in host:
                return [(2, 1, 6, '', ('8.8.8.8', 80))]
            elif "localhost" in host:
                return [(2, 1, 6, '', ('127.0.0.1', 80))]
            return [(2, 1, 6, '', ('0.0.0.0', 80))] # Default fallback

        mock_getaddrinfo.side_effect = getaddrinfo_side_effect

        with patch('requests.Session.get') as mock_get:
            # First response: Redirect to localhost
            r1 = MagicMock()
            r1.is_redirect = True
            r1.headers = {"Location": "http://localhost/secret"}

            # Second response (should not be reached if blocked correctly)
            r2 = MagicMock()
            r2.is_redirect = False
            r2.content = b"Secret Data"

            # We only expect the first call to succeed, then the check on the second URL should fail
            # so mock_get should only be called once.
            mock_get.return_value = r1

            result = self.scraper.scrape("http://safe.com/redirect")

            self.assertIn("error", result)
            self.assertIn("Security restricted IP", result["error"])
            # Verify we tried to verify localhost
            # (Implicitly verified by the error message)

if __name__ == "__main__":
    unittest.main()

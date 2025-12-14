
import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.heuristics import HeuristicAnalyzer

class TestTrustedEcosystem(unittest.TestCase):
    def setUp(self):
        self.heuristics = HeuristicAnalyzer()

    def test_google_ecosystem(self):
        # google.com -> youtube.com should be trusted
        self.assertTrue(self.heuristics._is_trusted_ecosystem("google.com", "youtube.com"), "google.com -> youtube.com should be trusted")
        # google.com -> drive.google.com should be trusted (subdomain)
        self.assertTrue(self.heuristics._is_trusted_ecosystem("google.com", "drive.google.com"), "google.com -> drive.google.com should be trusted")

    def test_microsoft_ecosystem(self):
        # microsoft.com -> office.com should be trusted
        self.assertTrue(self.heuristics._is_trusted_ecosystem("microsoft.com", "office.com"), "microsoft.com -> office.com should be trusted")
        # microsoft.com -> live.com should be trusted
        self.assertTrue(self.heuristics._is_trusted_ecosystem("microsoft.com", "live.com"), "microsoft.com -> live.com should be trusted")

    def test_amazon_ecosystem(self):
        # amazon.com -> aws.amazon.com should be trusted
        self.assertTrue(self.heuristics._is_trusted_ecosystem("amazon.com", "aws.amazon.com"), "amazon.com -> aws.amazon.com should be trusted")

    def test_untrusted(self):
        # google.com -> example.com should NOT be trusted
        self.assertFalse(self.heuristics._is_trusted_ecosystem("google.com", "example.com"), "google.com -> example.com should NOT be trusted")
        # microsoft.com -> google.com should NOT be trusted
        self.assertFalse(self.heuristics._is_trusted_ecosystem("microsoft.com", "google.com"), "microsoft.com -> google.com should NOT be trusted")

if __name__ == '__main__':
    unittest.main()

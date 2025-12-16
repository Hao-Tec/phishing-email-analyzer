import unittest
from src.heuristics import HeuristicAnalyzer
from src.config import WHITELIST_DOMAINS


class TestTyposquatting(unittest.TestCase):
    def setUp(self):
        self.analyzer = HeuristicAnalyzer()

    def test_paypal_typosquatting(self):
        # Data mirroring the critical sample
        email_data = {
            "sender": "security@paypa1.com",
            "subject": "Test",
            "body": "Test",
            "urls": []
        }

        # Verify paypal is in whitelist (prerequisite for logic)
        self.assertIn("paypal.com", WHITELIST_DOMAINS)

        # Run check directly
        self.analyzer._check_sender_anomalies(email_data)

        # Assertions
        findings = self.analyzer.details
        doppelganger_finding = next(
            (
                f for f in findings
                if f["heuristic"] == "doppelganger_domain"
            ),
            None
        )

        self.assertIsNotNone(
            doppelganger_finding,
            "Failed to detect 'paypa1.com' as typosquatting of 'paypal.com'"
        )
        self.assertEqual(doppelganger_finding["severity"], "HIGH")
        self.assertIn("paypal.com", doppelganger_finding["description"])


if __name__ == '__main__':
    unittest.main()

import unittest
from unittest.mock import patch, MagicMock
import json
from src.llm_analyzer import LLMAnalyzer


class TestLocalLLM(unittest.TestCase):

    @patch("src.llm_analyzer.LLM_PROVIDER", "local")
    @patch("src.llm_analyzer.requests.post")
    def test_local_llm_analysis(self, mock_post):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "is_phishing": True,
                                "confidence_score": 0.95,
                                "risk_level": "CRITICAL",
                                "reasoning": [
                                    "Urgent request",
                                    "Suspicious link",
                                ],
                                "summary": "This is a phishing email.",
                            }
                        )
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        # Initialize analyzer (it accepts provider from mocked
        # config import?)
        # Note: We need to patch LLM_PROVIDER in the module namespace
        # where it is used

        analyzer = LLMAnalyzer()
        # Manually force provider since __init__ might have run before
        # patch if we are not careful, but here we patch it before init.
        # Actually LLM_PROVIDER is imported at top level, so patching it
        # in test class might be tricky if not using reload. Let's force
        # it on instance for safety.
        analyzer.provider = "local"

        score, data = analyzer.analyze("Test email content")

        # Verify findings
        self.assertEqual(score, 0.95)
        self.assertEqual(data["risk_level"], "CRITICAL")
        self.assertTrue(data["is_phishing"])

        # Verify request structure
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("messages", kwargs["json"])
        self.assertEqual(kwargs["json"]["model"], "llama3")

    @patch("src.llm_analyzer.LLM_PROVIDER", "local")
    @patch("src.llm_analyzer.requests.post")
    def test_local_llm_connection_error(self, mock_post):
        # Simulate connection error
        mock_post.side_effect = Exception("Connection refused")

        analyzer = LLMAnalyzer()
        analyzer.provider = "local"

        score, data = analyzer.analyze("Test content")

        self.assertEqual(score, 0.0)
        self.assertIn("error", data)


if __name__ == "__main__":
    unittest.main()

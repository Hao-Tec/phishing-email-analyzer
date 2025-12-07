"""
LLM Analyzer Module
Uses Google Gemini to analyze emails for sophisticated phishing attempts.
"""

import os
import google.generativeai as genai
from typing import Dict, Tuple
import json


class LLMAnalyzer:
    """
    Analyzes email content using Google's Gemini Pro model.
    """

    def __init__(self):
        """Initialize the LLM analyzer with API key."""
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel("gemini-flash-latest")
        else:
            self.model = None

    def analyze(self, email_text: str) -> Tuple[float, Dict]:
        """
        Analyze email text using LLM.

        Args:
            email_text: The full text content of the email.

        Returns:
            Tuple containing:
            - Confidence score (0.0 to 1.0, where 1.0 is high confidence
              of phishing)
            - Analysis details dictionary
        """
        if not self.model:
            return 0.0, {"error": "No API key configured"}

        prompt = f"""
        You are a cybersecurity expert specializing in phishing detection.
        Analyze the following email for signs of phishing, social engineering,
        urgency, or other malicious intent.

        Email Content:
        '''
        {email_text[:4000]}  # Truncate to avoid token limits if necessary
        '''

        Provide your analysis in JSON format with the following keys:
        - is_phishing: boolean
        - confidence_score: float (0.0 to 1.0)
        - risk_level: string (LOW, MEDIUM, HIGH, CRITICAL)
        - reasoning: list of strings (key suspicious indicators)
        - summary: string (brief explanation of the verdict)

        Do not use markdown formatting in your response. Just the raw JSON
        string.
        """

        try:
            response = self.model.generate_content(prompt)
            data = self._parse_response(response.text)

            score = data.get("confidence_score", 0.0)
            # Normalize score to 0-100 scale for consistency with existing
            # system if needed,
            # but here we return 0-1 float as requested, handled by caller.

            return score, data

        except Exception as e:
            return 0.0, {"error": str(e)}

    def _parse_response(self, response_text: str) -> Dict:
        """Parse JSON response from LLM."""
        try:
            # Clean up markdown code blocks if present
            text = response_text.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]

            return json.loads(text.strip())
        except json.JSONDecodeError:
            return {
                "is_phishing": False,
                "confidence_score": 0.0,
                "risk_level": "UNKNOWN",
                "reasoning": ["Failed to parse LLM response"],
                "summary": "LLM analysis failed.",
            }

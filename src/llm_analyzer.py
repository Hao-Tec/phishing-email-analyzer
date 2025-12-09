"""
LLM Analyzer Module
Uses Google Gemini to analyze emails for sophisticated phishing attempts.
"""

import os
import google.generativeai as genai
from typing import Dict, Tuple
import json
import logging
import requests
from src.config import LLM_PROVIDER, LLM_LOCAL_URL, LLM_MODEL_NAME

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """
    Analyzes email content using Google's Gemini Pro model.
    """

    def __init__(self):
        """Initialize the LLM analyzer with API key or local config."""
        self.provider = LLM_PROVIDER
        self.model = None
        self.api_key = None

        if self.provider == "gemini":
            self.api_key = os.getenv("GEMINI_API_KEY")
            if self.api_key:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel("gemini-flash-latest")
        elif self.provider == "local":
            # No specific init needed for local, check url later
            pass

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
        if self.provider == "gemini" and not self.model:
            return 0.0, {"error": "No API key configured for Gemini"}

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
            if self.provider == "gemini":
                response = self.model.generate_content(prompt)
                response_text = response.text
            elif self.provider == "local":
                response_text = self._analyze_local(prompt)
            else:
                return 0.0, {"error": f"Unknown provider: {self.provider}"}

            data = self._parse_response(response_text)
            score = data.get("confidence_score", 0.0)
            return score, data

        except Exception as e:
            error_str = str(e)
            if "403" in error_str and "permission" in error_str.lower():
                logger.error(
                    "LLM Analysis failed: Permission Denied (403). "
                    "Check if GEMINI_API_KEY is correct and "
                    "'Generative Language API' is enabled in your "
                    "Google Cloud Console."
                )
            else:
                logger.error(f"LLM Analysis failed: {e}")

            return 0.0, {"error": str(e)}

    def _analyze_local(self, prompt: str) -> str:
        """Analyze using local LLM provider (OpenAI compatible API)."""
        payload = {
            "model": LLM_MODEL_NAME,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert.",
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }

        try:
            response = requests.post(LLM_LOCAL_URL, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            # Extract content from OpenAI format
            content = (
                result.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            return content
        except requests.exceptions.RequestException as e:
            raise Exception(f"Local LLM connection failed: {e}")

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

"""
LLM Analyzer Module
Uses Google Gemini to analyze emails for sophisticated phishing attempts.
"""

import os
import google.generativeai as genai
import requests
from typing import Dict, Tuple
import json
import socket
import logging
import sqlite3
import hashlib
from pathlib import Path
from src.config import (
    LLM_PROVIDER,
    LLM_LOCAL_URL,
    LLM_MODEL_NAME,
    LLM_CACHE_PATH,
)

logger = logging.getLogger(__name__)


class LLMCache:
    """
    Simple SQLite-based cache for LLM responses to save API quota/latency.
    """

    def __init__(self, db_path: str = LLM_CACHE_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database and table."""
        try:
            # Ensure directory exists
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS llm_cache (
                        hash TEXT PRIMARY KEY,
                        response TEXT
                    )
                    """
                )
        except Exception as e:
            logger.error(f"Failed to init LLM cache: {e}")

    def get(self, text: str) -> Dict:
        """Retrieve cached response for text if exists."""
        text_hash = self._hash_text(text)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT response FROM llm_cache WHERE hash = ?",
                    (text_hash,),
                )
                row = cursor.fetchone()
                if row:
                    try:
                        return json.loads(row[0])
                    except json.JSONDecodeError:
                        return None
        except Exception as e:
            logger.warning(f"Cache lookup failed: {e}")
        return None

    def put(self, text: str, response_data: Dict):
        """Store response in cache."""
        text_hash = self._hash_text(text)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO llm_cache (hash, response) "
                    "VALUES (?, ?)",
                    (text_hash, json.dumps(response_data)),
                )
        except Exception as e:
            logger.warning(f"Cache storage failed: {e}")

    def _hash_text(self, text: str) -> str:
        """Create SHA256 hash of the input text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LLMAnalyzer:
    """
    Analyzes email content using Google's Gemini Pro model.
    """

    def __init__(self):
        """Initialize the LLM analyzer with API key or local config."""
        self.provider = LLM_PROVIDER
        self.model = None
        self.api_key = None
        self.cache = LLMCache()

        if self.provider == "gemini":
            self.api_key = os.getenv("GEMINI_API_KEY")
            if self.api_key:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel("gemini-flash-latest")
        elif self.provider == "local":
            # No specific init needed for local, check url later
            pass

    def analyze(
        self, email_text: str, url_content: Dict = None
    ) -> Tuple[float, Dict]:
        """
        Analyze email text using LLM.

        Args:
            email_text: The full text content of the email.
            url_content: Optional scraped content from URLs in the email.

        Returns:
            Tuple containing:
            - Confidence score (0.0 to 1.0, where 1.0 is high confidence
              of phishing)
            - Analysis details dictionary
        """
        if self.provider == "gemini" and not self.model:
            return 0.0, {"error": "No API key configured for Gemini"}

        # Check cache first
        cached_result = self.cache.get(email_text)
        if cached_result:
            logger.info("LLM Cache Hit")
            score = cached_result.get("confidence_score", 0.0)
            # Add cache indicator for UI/Transparency
            cached_result["cached"] = True
            return score, cached_result

        # Prepare URL context if available
        url_context = ""
        if url_content:
            url_context = f"""
            Scraped URL Content (The link in the email leads here):
            URL: {url_content.get('url')}
            Page Title: {url_content.get('title')}
            Page Text Snippet:
            '''
            {url_content.get('text', '')[:1000]}
            '''
            """

        prompt = f"""
        You are a cybersecurity expert specializing in phishing detection.
        Analyze the following email for signs of phishing, social engineering,
        urgency, or other malicious intent.

        Email Content:
        '''
        {email_text[:4000]}  # Truncate to avoid token limits if necessary
        '''

        {url_context}

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
                # FAST FAIL: Check connectivity before invoking the heavy client
                # (Prevents indefinite retries/hanging on DNS failure)
                if not self._check_connectivity():
                    logger.warning("Network unreachable: Skipping AI analysis.")
                    return 0.0, {"error": "Network unavailable (Offline)"}

                response = self.model.generate_content(prompt)
                response_text = response.text
            elif self.provider == "local":
                response_text = self._analyze_local(prompt)
            else:
                return 0.0, {"error": f"Unknown provider: {self.provider}"}

            data = self._parse_response(response_text)

            # Cache the successful result
            if "error" not in data:
                # Store original text as key, not prompt, to match input
                self.cache.put(email_text, data)

            score = data.get("confidence_score", 0.0)
            return score, data

        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "quota" in error_str.lower():
                logger.warning("LLM Analysis unavailable: Quota exceeded.")
                return 0.0, {"error": "Quota exceeded (429)"}
            elif "403" in error_str and "permission" in error_str.lower():
                logger.error("LLM Permission Error: Check API Key/Billing.")
                return 0.0, {"error": "Permission denied (403)"}
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
            if text.startswith("`json"):
                text = text[7:]
            if text.startswith("`"):
                text = text[3:]
            if text.endswith("`"):
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

    def _check_connectivity(self) -> bool:
        """
        Fast check if Gemini API is reachable.
        Avoids the 60s+ retry loop if we are offline.
        """
        try:
            # Resolve the specific API host (or common reliable host)
            socket.gethostbyname("generativelanguage.googleapis.com")
            return True
        except socket.error:
            return False

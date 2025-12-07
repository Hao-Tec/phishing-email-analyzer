"""
Machine Learning Analyzer Module
Uses local ML models (scikit-learn) to detect phishing patterns.
"""

import os
import pickle
import logging
from typing import Tuple, Dict

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
except ImportError:
    TfidfVectorizer = None
    RandomForestClassifier = None
    np = None

from src.config import ML_MODEL_PATH, ML_VECTORIZER_PATH


class MLAnalyzer:
    """
    Analyzes email content using a machine learning model.
    """

    def __init__(self):
        """Initialize the ML analyzer."""
        self.model = None
        self.vectorizer = None
        self.enabled = False

        if TfidfVectorizer and RandomForestClassifier:
            self._load_model()

    def _load_model(self):
        """Load the model and vectorizer from disk."""
        try:
            if os.path.exists(ML_MODEL_PATH) and os.path.exists(ML_VECTORIZER_PATH):
                with open(ML_MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(ML_VECTORIZER_PATH, "rb") as f:
                    self.vectorizer = pickle.load(f)
                self.enabled = True
            else:
                logging.info(
                    f"ML model not found at {ML_MODEL_PATH}. " "ML analysis disabled."
                )
        except Exception as e:
            logging.error(f"Failed to load ML model: {e}")
            self.enabled = False

    def analyze(self, text: str) -> Tuple[float, Dict]:
        """
        Analyze text using the ML model.

        Args:
            text: Email body text

        Returns:
            Tuple (probability_score, details_dict)
        """
        if not self.enabled or not text:
            return 0.0, {}

        try:
            # Transform text
            features = self.vectorizer.transform([text])

            # Predict
            prob = self.model.predict_proba(features)[0][
                1
            ]  # Probability of class 1 (Phishing)

            return prob, {
                "ml_probability": float(prob),
                "model_used": "RandomForest",
                "risk_assessment": (
                    "High" if prob > 0.8 else "Medium" if prob > 0.5 else "Low"
                ),
            }
        except Exception as e:
            logging.error(f"ML prediction error: {e}")
            return 0.0, {"error": str(e)}

    # Optional: Method to train a dummy model for testing purposes
    # if none exists
    def train_dummy_model(self):
        """Train a basic model for demonstration if file doesn't exist."""
        if self.enabled:
            return  # Already loaded

        if not TfidfVectorizer:
            return

        logging.info("Training dummy ML model for demonstration...")
        # Simple dataset
        texts = [
            "Hello, how are you?",
            "Meeting at 3pm",
            "Verify your account now",
            "Click here to claim prize",
            "Urgent: Account suspended",
        ]
        labels = [0, 0, 1, 1, 1]  # 0 = Safe, 1 = Phishing

        self.vectorizer = TfidfVectorizer()
        X = self.vectorizer.fit_transform(texts)
        self.model = RandomForestClassifier(n_estimators=10)
        self.model.fit(X, labels)
        self.enabled = True

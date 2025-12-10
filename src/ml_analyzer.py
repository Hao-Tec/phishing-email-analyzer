"""
Machine Learning Analyzer Module
Uses local ML models (scikit-learn) to detect phishing patterns.
Supports loading vast external datasets (JSON) or falling back to
embedded data.
"""

import os
import json
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

from src.config import (
    ML_MODEL_PATH,
    ML_VECTORIZER_PATH,
    DATASET_PATH,
    PHISHING_TRAINING_DATA,
)


class MLAnalyzer:
    """
    Analyzes email content using a machine learning model.
    """

    def __init__(self):
        """Initialize the ML analyzer."""
        self.model = None
        self.vectorizer = None
        self.enabled = False

        # URL Model
        self.url_model = None
        self.url_vectorizer = None

        if TfidfVectorizer and RandomForestClassifier:
            self._load_model()
            self._load_url_model()
            # If load failed (no model yet), train the embedded one
            if not self.enabled:
                self.train_model()

    def _load_model(self):
        """Load the model and vectorizer from disk."""
        try:
            has_model = os.path.exists(ML_MODEL_PATH)
            has_vec = os.path.exists(ML_VECTORIZER_PATH)
            if has_model and has_vec:
                with open(ML_MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(ML_VECTORIZER_PATH, "rb") as f:
                    self.vectorizer = pickle.load(f)
                self.enabled = True
                logging.info(f"Loaded ML model from {ML_MODEL_PATH}")
            else:
                logging.info(f"ML model absent at {ML_MODEL_PATH}. Training.")
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

    def train_model(self):
        """
        Train the model using the best available data source.
        1. Try DATASET_PATH (Vast JSON dataset)
        2. Fallback to PHISHING_TRAINING_DATA (Embedded config)
        """
        if self.enabled:
            logging.info("Model already loaded. Re-training requested...")

        if not TfidfVectorizer:
            logging.error("Scikit-learn not installed. ML disabled.")
            return

        texts = []
        labels = []
        source = "embedded"

        # 1. Try Loading Advanced Dataset
        if os.path.exists(DATASET_PATH):
            try:
                logging.info(f"Loading data: {DATASET_PATH}")
                with open(DATASET_PATH, "r") as f:
                    data = json.load(f)
                    for item in data:
                        texts.append(item.get("text", ""))
                        labels.append(item.get("label", 0))
                source = f"external_json ({len(texts)} samples)"
            except Exception as e:
                logging.error(f"Failed to load external dataset: {e}")

        # 2. Fallback to Embedded Data
        if not texts:
            logging.warning("Ext dataset missing. Using embedded.")
            texts = [item[0] for item in PHISHING_TRAINING_DATA]
            labels = [item[1] for item in PHISHING_TRAINING_DATA]
            source = f"embedded_config ({len(texts)} samples)"

        logging.info(f"Training Model on {source}...")

        try:
            # Vectorize
            # Increased max_features for larger datasets
            self.vectorizer = TfidfVectorizer(
                stop_words="english",
                max_features=3000
            )
            X = self.vectorizer.fit_transform(texts)

            # Train Model
            # Increased estimators for better accuracy
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
            self.model.fit(X, labels)

            # Save Artifacts
            os.makedirs(os.path.dirname(ML_MODEL_PATH), exist_ok=True)
            with open(ML_MODEL_PATH, "wb") as f:
                pickle.dump(self.model, f)
            with open(ML_VECTORIZER_PATH, "wb") as f:
                pickle.dump(self.vectorizer, f)

            self.enabled = True
            logging.info(f"Model trained on {len(texts)} samples.")

        except Exception as e:
            logging.error(f"Failed to train model: {e}")
            self.enabled = False

    # --- URL Analysis Extensions ---

    def _load_url_model(self):
        """Load the URL-specific model and vectorizer."""
        try:
            from src.config import ML_URL_MODEL_PATH, ML_URL_VECTORIZER_PATH

            if os.path.exists(ML_URL_MODEL_PATH) and os.path.exists(
                ML_URL_VECTORIZER_PATH
            ):
                with open(ML_URL_MODEL_PATH, "rb") as f:
                    self.url_model = pickle.load(f)
                with open(ML_URL_VECTORIZER_PATH, "rb") as f:
                    self.url_vectorizer = pickle.load(f)
                logging.info(f"Loaded URL ML model from {ML_URL_MODEL_PATH}")
            else:
                logging.warning(
                    "URL ML model not found. "
                    "Run tools/train_url_model.py to enable."
                )
        except Exception as e:
            logging.error(f"Failed to load URL ML model: {e}")

    def analyze_url(self, url: str) -> float:
        """
        Predict phishing probability for a URL.
        Returns 0.0 to 1.0 (1.0 = Phishing).
        """
        if not self.url_model or not self.url_vectorizer or not url:
            return 0.0

        try:
            features = self.url_vectorizer.transform([url])
            prob = self.url_model.predict_proba(features)[0][1]
            return float(prob)
        except Exception as e:
            logging.error(f"URL ML prediction error: {e}")
            return 0.0

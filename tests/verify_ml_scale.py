import sys
import os
import logging

# Configure logging to show info/errors
logging.basicConfig(level=logging.INFO)

# Add root to path
sys.path.append(os.getcwd())

try:
    import sklearn

    print(f"PASS: sklearn installed (version {sklearn.__version__})")
except ImportError:
    print("FAIL: sklearn NOT installed.")

from src.ml_analyzer import MLAnalyzer
from src.config import DATASET_PATH


def verify_training():
    print("--- Verifying Advanced ML Training ---")

    # 1. Check Dataset Exists
    if not os.path.exists(DATASET_PATH):
        print(f"FAIL: Dataset not found at {DATASET_PATH}")
        sys.exit(1)

    print(f"PASS: Dataset found at {DATASET_PATH}")

    # 2. Force Retraining
    model_path = "models/phishing_model.pkl"
    if os.path.exists(model_path):
        try:
            os.remove(model_path)
            print("Removed existing model to force validation.")
        except:
            pass

    # 3. Initialize Analyzer (Triggers Training)
    print("Initializing Analyzer...")
    analyzer = MLAnalyzer()

    # 4. Assertions
    if not analyzer.enabled:
        print("FAIL: Analyzer failed to initialize/train. See logs above.")
        sys.exit(1)

    vocab_size = len(analyzer.vectorizer.vocabulary_)
    print(f"Model Vocabulary Size: {vocab_size}")

    if vocab_size < 150:
        print(
            "FAIL: Vocabulary too small. Likely used embedded data instead of vast dataset."
        )
        sys.exit(1)

    print(f"PASS: Model trained with vast vocabulary ({vocab_size} tokens).")

    # 5. Test Prediction
    sample = "Urgent: CEO wire transfer request to foreign account"
    score, details = analyzer.analyze(sample)
    print(f"Test Prediction for '{sample}': {score:.4f}")

    if score > 0.7:
        print("PASS: High confidence detection.")
    else:
        print("WARNING: Detection confidence low.")


if __name__ == "__main__":
    verify_training()

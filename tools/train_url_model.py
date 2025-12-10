import os
import csv
import sys
import pickle
import random
import logging

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import ML_URL_MODEL_PATH, ML_URL_VECTORIZER_PATH

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
except ImportError:
    logger.error("scikit-learn not installed. Please run: pip install scikit-learn")
    sys.exit(1)


def load_datasets():
    """Load and combine datasets from CSV files."""
    urls = []
    labels = []

    # Dataset 1: Phishing URLs.csv (All are phishing)
    path1 = os.path.join("Phishing URL dataset", "Phishing URLs.csv")
    if os.path.exists(path1):
        try:
            with open(path1, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) >= 1:
                        urls.append(row[0])
                        labels.append(1)  # Phishing
            logger.info(f"Loaded from {path1}: {len(urls)} samples")
        except Exception as e:
            logger.error(f"Error loading {path1}: {e}")

    # Dataset 2: URL dataset.csv (Mixed)
    path2 = os.path.join("Phishing URL dataset", "URL dataset.csv")
    start_len = len(urls)
    if os.path.exists(path2):
        try:
            with open(path2, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if len(row) >= 2:
                        url = row[0]
                        type_label = row[1].lower()
                        if type_label == "phishing":
                            urls.append(url)
                            labels.append(1)
                        elif type_label == "legitimate":
                            urls.append(url)
                            labels.append(0)
            logger.info(f"Loaded from {path2}: {len(urls) - start_len} samples")
        except Exception as e:
            logger.error(f"Error loading {path2}: {e}")

    return urls, labels


def train():
    urls, labels = load_datasets()

    if not urls:
        logger.error("No data found to train on. Check CSV paths.")
        return

    logger.info(f"Total samples: {len(urls)}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        urls, labels, test_size=0.2, random_state=42
    )

    logger.info("Vectorizing URLs (Character-level TF-IDF)...")
    # Character n-grams are very effective for URLs to catch obfuscation, funny domains, etc.
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=5000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    logger.info("Training Random Forest Classifier (this may take a moment)...")
    # n_jobs=-1 uses all CPU cores
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    clf.fit(X_train_vec, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    logger.info(f"Model Accuracy: {acc*100:.2f}%")
    logger.info(
        "\n"
        + classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    )

    # Save artifacts
    os.makedirs(os.path.dirname(ML_URL_MODEL_PATH), exist_ok=True)

    logger.info(f"Saving model to {ML_URL_MODEL_PATH}...")
    with open(ML_URL_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)

    logger.info(f"Saving vectorizer to {ML_URL_VECTORIZER_PATH}...")
    with open(ML_URL_VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)

    logger.info("Done!")


if __name__ == "__main__":
    train()

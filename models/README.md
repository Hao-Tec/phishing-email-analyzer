# Models Directory

This directory is intended to store trained machine learning models used by the Phishing Email Analyzer.

## Auto-Generation

You generally **do not** need to manually download or place files here.

- When you run the analyzer (e.g., `python main.py ...`), the `MLAnalyzer` component will check for existing models.
- If no models are found, it will **automatically train** a new Random Forest model using the dataset provided in `data/phishing_dataset_v2.json`.
- The trained model (`phishing_model.pkl`) and vectorizer (`vectorizer.pkl`) will be saved here for future use.

## Pre-trained Models

If you wish to distribute pre-trained models to skip the initial training step (which is usually fast), you can place the `.pkl` files here.

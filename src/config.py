"""
Configuration file for phishing detection heuristics and thresholds.
"""

# Phishing suspicion score thresholds
SCORE_THRESHOLD = {
    "SAFE": 0,
    "LOW_RISK": 30,
    "MEDIUM_RISK": 60,
    "HIGH_RISK": 85,
    "CRITICAL": 100,
}

# Risk level classification
RISK_LEVELS = {
    0: "SAFE",
    30: "LOW_RISK",
    60: "MEDIUM_RISK",
    85: "HIGH_RISK",
    100: "CRITICAL",
}

# Heuristic weights (contribute to final score)
HEURISTIC_WEIGHTS = {
    "sender_domain_mismatch": 20,
    "url_mismatch_with_text": 25,
    "url_obfuscation": 15,
    "suspicious_attachment": 20,
    "header_anomalies": 10,
    "urgent_language": 5,
    "suspicious_tld": 10,
    "ip_based_url": 15,
    "llm_analysis": 30,
    "authentication_failure": 30,
    "virustotal_positive": 100,
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".vbs",
    ".js",
    ".zip",
    ".rar",
    ".dll",
    ".msi",
    ".ps1",
    ".pif",
    ".com",
    ".jar",
    ".app",
}

# Common legitimate domains (whitelist)
WHITELIST_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "protonmail.com",
    "microsoft.com",
    "apple.com",
    "google.com",
    "amazon.com",
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".su", ".zip"}

# Urgent/threatening keywords that increase suspicion
URGENT_KEYWORDS = {
    "verify",
    "confirm",
    "urgent",
    "immediate",
    "act now",
    "click here",
    "update",
    "authenticate",
    "validate",
    "suspended",
    "locked",
    "unusual activity",
    "congratulations",
}

# Maximum URL length before suspicious (typically longer for obfuscation)
MAX_URL_LENGTH = 100

# Minimum URL length that's considered valid
MIN_URL_LENGTH = 10

# --- New Configurations for Enhancements ---

# External API Keys
# (Load from env vars in real app, these are placeholders/names)
PHISHTANK_API_KEY_ENV = "PHISHTANK_API_KEY"
SAFE_BROWSING_API_KEY_ENV = "SAFE_BROWSING_API_KEY"

# ML Model Paths
ML_MODEL_PATH = "models/phishing_model.pkl"
ML_VECTORIZER_PATH = "models/vectorizer.pkl"

# OCR Configuration
# If Tesseract is not in PATH, specify absolute path here
# e.g., r"C:\Program Files\Tesseract-OCR\tesseract.exe"
TESSERACT_CMD_PATH = None

# Update Heuristic Weights with new components
HEURISTIC_WEIGHTS.update(
    {
        "ml_confidence_high": 40,
        "ocr_suspicious_content": 20,
        "external_db_positive": 100,  # Critical if found in Ext DBs
        "auth_dkim_fail": 25,
        "auth_spf_fail": 25,
        "auth_dmarc_fail": 25,
    }
)

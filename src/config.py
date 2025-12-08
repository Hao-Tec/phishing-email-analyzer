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
    "linkedin.com",
}

# Trusted Domain Groups (Eco-systems)
# Maps a primary domain to its known safe related domains
TRUSTED_DOMAIN_GROUPS = {
    "microsoft.com": {
        "aka.ms",
        "office.com",
        "office365.com",
        "microsoftonline.com",
        "azure.com",
        "msdn.com",
        "visualstudio.com",
        "linkedin.com",
        "github.com",
        "live.com",
    },
    "google.com": {
        "goo.gl",
        "youtube.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
    },
    "amazon.com": {
        "aws.amazon.com",
        "ssl-images-amazon.com",
        "media-amazon.com",
    },
}

# Platform domains that are commonly used for legitimate business/events
# Links to these domains should NOT trigger a "Mismatch" alert even if
# sender differs
PLATFORM_DOMAINS = {
    "zoho.com",
    "zoho.in",
    "zoom.us",
    "teams.microsoft.com",
    "meet.google.com",
    "docs.google.com",
    "drive.google.com",
    "dropbox.com",
    "slack.com",
    "trello.com",
    "atlassian.net",
    "jira.com",
    "bitbucket.org",
    "github.com",
    "gitlab.com",
    "mailchimp.com",
    "surveymonkey.com",
    "eventbrite.com",
    "lu.ma",
    "meetup.com",
}

# Maximum score contribution per heuristic type
# Prevents a single issue (like many long URLs) from becoming CRITICAL
MAX_SCORE_CONTRIBUTION = {
    "url_obfuscation": 30,
    "url_mismatch_with_text": 40,
    "sender_domain_mismatch": 40,
    "suspicious_tld": 20,
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
MAX_URL_LENGTH = 200

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

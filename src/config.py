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

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
    "doppelganger_domain": 85,  # High risk
    "ip_based_url": 15,
    "llm_analysis": 50,  # Boosted for "Advanced" analysis
    "authentication_failure": 30,
    "virustotal_positive": 100,
}

# Embedded Training Data for Local ML (Zero-Day Pattern Recognition)
# Seeds the model with known "Intent Patterns" to detect generic phishing
# content even without external updates.
PHISHING_TRAINING_DATA = [
    # CLASS 1: PHISHING (Malicious Intent)
    ("Urgent: Your account will be suspended immediately", 1),
    ("Verify your identity within 24 hours to avoid lock", 1),
    ("Click here to claim your lottery winnings now", 1),
    ("Unusual sign-in activity detected from Russia", 1),
    ("Payment overdue: Invoice attached #99283", 1),
    ("CEO Request: Wire transfer needed urgently", 1),
    ("HR Update: Review the new salary structure", 1),
    ("Microsoft 365: Password expiration notice", 1),
    ("Deactivate request received. Cancel if not you.", 1),
    ("Your package delivery attempted failed. Reschedule.", 1),
    ("Confirm your bitcoin wallet credentials", 1),
    ("IRS Notification: Tax refund pending", 1),
    ("Netflix: Subscription payment failed", 1),
    ("DocuSign: Please sign 'Contract_FWD.pdf'", 1),
    ("Zoom: Missed meeting with HR. Recording available.", 1),
    ("Kindly purchase iTunes gift cards for the team", 1),
    ("Security Alert: New device logged in", 1),
    ("Final Reminder: Update your payment information", 1),
    ("Exclusive Offer: 90% discount expires today", 1),
    ("Unauthorized access attempt blocked", 1),
    # CLASS 0: SAFE (Normal Business Comms)
    ("Meeting notes from today's sync", 0),
    ("Can we reschedule our 1:1 to tomorrow?", 0),
    ("Project timeline update - Q1 Goals", 0),
    ("Lunch menu for the team event", 0),
    ("Happy Birthday to our team member!", 0),
    ("Attached is the quarterly report for review", 0),
    ("Please find the requested documents attached", 0),
    ("Let's connect on LinkedIn", 0),
    ("Invitation: Annual Company Picnic", 0),
    ("Feedback on the new design draft", 0),
    ("Reminder: Submit your timesheets by Friday", 0),
    ("Thank you for your business", 0),
    ("Flight confirmation for your upcoming trip", 0),
    ("Hotel reservation confirmed: Hilton", 0),
    ("Welcome to the team! Onboarding info.", 0),
    ("Great job on the presentation today", 0),
    ("Checking in on the status of ticket #123", 0),
    ("Recipe for the potluck", 0),
    ("Office closure / Holiday announcement", 0),
    ("Please ignore previous email, sent in error", 0),
]

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
    # --- Top Tech & Social Media ---
    # --- Top Tech & Social Media ---
    "gmail.com", "google.com", "youtube.com", "docs.google.com",
    "drive.google.com", "microsoft.com", "outlook.com", "office.com",
    "teams.microsoft.com", "azure.com", "sharepoint.com", "onedrive.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "aws.amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "twitter.com", "x.com", "linkedin.com", "slack.com", "discord.com",
    "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com",
    "netflix.com", "spotify.com", "twitch.tv", "hulu.com", "disneyplus.com",

    # --- Financial & Payment Services ---
    "paypal.com", "stripe.com", "venmo.com", "cash.app", "wise.com",
    "visa.com", "mastercard.com", "amex.com", "americanexpress.com",
    "discover.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citi.com", "citibank.com", "capitalone.com", "usbank.com", "pnc.com",
    "td.com", "truist.com", "hsbc.com", "barclays.com", "santander.com",
    "db.com", "ubs.com", "coinbase.com", "binance.com", "blockchain.com",
    "crypto.com", "kraken.com", "schwab.com", "fidelity.com",
    "vanguard.com", "etrade.com", "robinhood.com", "intuit.com", "irs.gov",

    # --- Logistics & E-commerce ---
    "fedex.com", "ups.com", "dhl.com", "usps.com", "royalmail.com",
    "walmart.com", "target.com", "bestbuy.com", "ebay.com", "etsy.com",
    "alibaba.com", "aliexpress.com", "shopify.com", "costco.com",
    "homedepot.com",

    # --- Enterprise & Cloud Services ---
    "dropbox.com", "box.com", "salesforce.com", "atlassian.com",
    "trello.com", "jira.com", "confluence.com", "bitbucket.org",
    "github.com", "gitlab.com", "zoom.us", "webex.com",
    "gotomeeting.com", "docusign.com", "adobe.com", "okta.com",
    "servicenow.com", "oracle.com", "sap.com", "ibm.com", "cisco.com",
    "dell.com", "hp.com", "lenovo.com", "intel.com",

    # --- Other Common Phishing Targets ---
    "yahoo.com", "aol.com", "protonmail.com", "zoho.com", "yandex.com",
    "airbnb.com", "booking.com", "expedia.com", "uber.com", "lyft.com",
    "roblox.com", "steamcommunity.com", "blizzard.com", "ea.com",
    "att.com", "verizon.com", "t-mobile.com", "vodafone.com",
    "orange.com", "who.int", "cdc.gov", "un.org",

    # --- African Fintech & Regional Banks ---
    "moniepoint.com", "flutterwave.com", "paystack.com", "opay.ng",
    "kuda.com", "piggyvest.com", "chipper.com", "interswitch.com",
    "gtbank.com", "firstbanknigeria.com", "accessbankplc.com",
    "zenithbank.com", "ubagroup.com", "sterlingbank.com",
    "mtn.com", "gloworld.com", "airtelafrica.com",

    # --- Email Infrastructure (Marketing/Transactional) ---
    "sendgrid.net", "sendgrid.com", "mailchimp.com", "mailgun.com",
    "amazonses.com", "postmarkapp.com", "sparkpost.com",
    "ct.sendgrid.net",  # SendGrid click tracking domain
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
    # Email Marketing Platforms - their tracking links are legitimate
    "sendgrid.net": {
        "ct.sendgrid.net",
        "u8065049.ct.sendgrid.net",  # User-specific tracking subdomain
        "sendgrid.com",
    },
    "mailchimp.com": {
        "list-manage.com",
        "mailchi.mp",
    },
    # African Fintech - their CDN and tracking domains
    "moniepoint.com": {
        "em3749.moniepoint.com",  # Email subdomain
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

# Suspicious keywords that indicate phishing attempts
SUSPICIOUS_KEYWORDS = URGENT_KEYWORDS  # Alias for compatibility

# Maximum URL length before suspicious (typically longer for obfuscation)
MAX_URL_LENGTH = 200

# Email infrastructure domains - these use long tracking URLs by design
# Skip URL obfuscation checks for these domains
EMAIL_INFRASTRUCTURE_DOMAINS = {
    "sendgrid.net", "ct.sendgrid.net", "sendgrid.com",
    "mailchimp.com", "list-manage.com", "mailchi.mp",
    "mailgun.com", "postmarkapp.com", "sparkpost.com",
    "amazonses.com", "ses.amazonaws.com",
    "constantcontact.com", "campaign-archive.com",
    "hubspot.com", "hs-sites.com",
    "messagelabs.com", "mimecast.com",
}

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
DATASET_PATH = "data/phishing_dataset_v2.json"

ML_URL_MODEL_PATH = "models/url_model.pkl"
ML_URL_VECTORIZER_PATH = "models/url_vectorizer.pkl"

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

# Configuration for Gemini Data Generation
GENERATION_CONFIG = {
    "phishing_prompt": """
    Generate 5 distinct, sophisticated phishing email examples.
    Focus on these categories: CEO Fraud, Account Suspension,
    Spear Phishing (HR/IT), Crypto Scams, fake invoice.
    Return ONLY a JSON list of objects with 'text' (body) and 'label' (1).
    Do not include markdown formatting.
    """,
    "safe_prompt": """
    Generate 5 distinct, safe business email examples.
    Focus on: Meeting invites, project updates, newsletters,
    friendly check-ins, system notifications (legitimate).
    Return ONLY a JSON list of objects with 'text' (body) and 'label' (0).
    Do not include markdown formatting.
    """,
}

# LLM Provider Configuration
# Options: "gemini", "local"
LLM_PROVIDER = "gemini"

# Local LLM Configuration (e.g., for Ollama)
LLM_LOCAL_URL = "http://localhost:11434/v1/chat/completions"
# Model name to request from local provider
LLM_MODEL_NAME = "llama3"

# LLM Cache Configuration
# Path to SQLite database for caching analysis results
LLM_CACHE_PATH = "data/llm_cache.db"

# Phishing Email Analyzer - Architecture & Extension Guide

## Project Structure

```
Lockin/
├── main.py                 # CLI entry point
├── requirements.txt        # Python dependencies
├── README.md               # User documentation
├── ARCHITECTURE.md         # This file
├── IMPLEMENTATION_SUMMARY.md # Status & Features Summary
├── quickstart.py           # Rapid setup script
│
├── src/                    # Main package
│   ├── __init__.py
│   ├── config.py           # Centralized configuration
│   ├── email_parser.py     # Universal Email parsing (EML, MSG, GZ)
│   ├── heuristics.py       # Static detection heuristics
│   ├── analyzer.py         # Central Orchestrator
│   ├── reporter.py         # Report generation
│   ├── auth_validator.py   # [NEW] DKIM/SPF/DMARC verification
│   ├── ml_analyzer.py      # [NEW] Local Machine Learning
│   ├── image_analyzer.py   # [NEW] OCR Analysis
│   ├── vt_scanner.py       # VirusTotal Integration
│   ├── llm_analyzer.py     # LLM Analysis (Gemini/Local)
│   ├── external_scanners.py# Threat Intel API integrations
│   └── url_scraper.py      # [NEW] Real-time URL content fetching
│
│
├── tools/                  # Dataset Generation & Maintenance Tools
│   └── generate_advanced_dataset.py
├── data/                   # [NEW] Local datasets
│   └── phishing_dataset_v2.json
├── models/                 # ML Models directory
├── tests/                  # Test suite
└── samples/                # Sample test emails
```

## Module Responsibilities

### Core Modules

**analyzer.py (EmailAnalyzer)**
The brain of the operation. It initializes all sub-components and runs them in sequence:

1.  Parser extracts data.
2.  ImageAnalyzer extracts text from images (OCR).
3.  Heuristics run on text + OCR content.
4.  AuthValidator checks transport security.
5.  MLAnalyzer predicts phishing probability.
6.  ExternalScanners check URLs.
7.  LLMAnalyzer performs semantic analysis (Gemini or Local).
8.  Aggregates all scores into a final Risk Level.

**email_parser.py (EmailParser)**

- **Expanded Capability**: Now supports `.msg` (via `extract-msg`) and `.eml.gz` (via `gzip`).
- **Raw Content**: Preserves raw bytes for DKIM verification.
- **OCR Prep**: Extracts image attachments for the ImageAnalyzer.

### New Detection Modules

**auth_validator.py (AuthValidator)**

- **Purpose**: Active verification of email authenticity.
- **Key Methods**: `validate(raw_bytes, headers, sender)`
- **Logic**:
  - **DKIM**: Verifies cryptographic signatures using `dkimpy`.
  - **SPF**: DNS lookup to verify sender IP authorization.
  - **DMARC**: DNS lookup for policy enforcement.

**ml_analyzer.py (MLAnalyzer)**

- **Purpose**: Fast, local statistical detection & Zero-Day protection.
- **Key Methods**: `analyze(text)`, `train_model()`
- **Logic**:
  - Uses a pre-trained `scikit-learn` pipeline (TF-IDF + RandomForest).
  - **Auto-Training**: If model is missing, automatically trains on `data/phishing_dataset_v2.json` (1000+ samples) or falls back to embedded patterns.
  - **Persistence**: Saves trained models to `models/` for future runs.

**image_analyzer.py (ImageAnalyzer)**

- **Purpose**: Reveal hidden text in images.
- **Key Methods**: `extract_text_from_images(attachments)`
- **Logic**: Bridges Python and the `tesseract` binary to perform OCR on image attachments.

**external_scanners.py (ExternalScanners)**

- **Purpose**: Real-time reputation checks.
- **Key Methods**: `scan_url(url)`
- **Integration**:
  - **Google Safe Browsing**: Checks against malware/social engineering lists.
  - **PhishTank**: Checks against community-verified phishing URLs.

**url_scraper.py (URLScraper)**

- **Purpose**: Real-time content analysis of suspect links.
- **Key Methods**: `scrape(url)`
- **Logic**:
  - Fetches the target URL with a standard user-agent.
  - Extracts page title and visible text using `BeautifulSoup`.
  - Fetches the target URL with a standard user-agent.
  - Extracts page title and visible text using `BeautifulSoup`.
  - **Error Handling**: Gracefully reports DNS failures and timeouts as findings, without crashing.
  - Feeds the _actual_ page content to the LLM for deep analysis.

**llm_analyzer.py (LLMAnalyzer)**

- **Connectivity**: Implements "Fast Fail" checks to prevent hanging on network outages.
- **Resilience**: Skips AI analysis gracefully if Gemini API is unreachable.

**reporter.py (EmailReporter)**

- **Features**: Generates HTML reports with interactive glossaries explaining technical terms (SPF, DKIM, Typosquatting) to end-users.

**heuristics.py (HeuristicAnalyzer)**

- **Typosquatting**: Enhanced detection using a whitelist of 100+ high-value domains (PayPal, Google, Banks) to catch "doppelganger" domains (e.g., `paypa1.com`).

## Data Flow

```
Email File (.eml/.msg)
    ↓
EmailParser
    ├── Metadata (Headers, Body)
    ├── Raw Bytes (for Auth)
    └── Attachments (for OCR)
    ↓
ImageAnalyzer (OCR) → Appends text to Body
    ↓
Parallel Analysis:
    ├── AuthValidator (DKIM/SPF)
    ├── Heuristics (Static Rules)
    ├── MLAnalyzer (Random Forest)
    ├── ExternalScanners (SafeBrowsing/PhishTank)
    ├── URLScraper (Fetches page content)
    └── LLMAnalyzer (Gemini or Local LLM + SQLite Cache)
    ↓
EmailAnalyzer (Aggregator)
    ↓
Final Risk Score & Findings
    ↓
EmailReporter (HTML/JSON)
```

## Extending the Tool

### Adding a New Model

To train and use your own ML model:

1.  Train a model using `scikit-learn`.
2.  Save the vectorizer to `models/vectorizer.pkl`.
3.  Save the classifier to `models/phishing_model.pkl`.
4.  The `MLAnalyzer` will automatically load it on next run.

### Adding a New External Source

1.  Modify `src/external_scanners.py`.
2.  Add a new method `_check_new_source(url)`.
3.  Call it in `scan_url()`.
4.  Add API keys to `.env` and `src/config.py`.

# Phishing Email Analyzer

A world-class, enterprise-grade phishing detection system designed to identify sophisticated email threats. This tool integrates active authentication verification, local machine learning, image-based OCR analysis, and external threat intelligence to provide a comprehensive security assessment of suspicious emails.

![CI](https://github.com/Hao-Tec/phishing-email-analyzer/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 Key Features

### 🛡️ active Defense Layer

- **Authentication Verification (DKIM/SPF/DMARC)**: Actively validates sender identity protocols to detect spoofing attempts with high precision.
- **External Threat Intelligence**: Real-time cross-referencing of URLs against **Google Safe Browsing** and **PhishTank** databases.
- **VirusTotal Integration**: Scans URLs against 70+ antivirus engines for maximum threat coverage.

### 🧠 Intelligent Analysis

- **Machine Learning Engine**: Built-in local Random Forest model (scikit-learn) trained to detect phishing linguistic patterns with high confidence.
- **Generative AI Integration**: Leverages **Google Gemini LLM** for deep semantic analysis, detecting social engineering nuances that rule-based systems miss.
- **Visual OCR Analysis**: Uses **Tesseract OCR** to extract and analyze text embedded in images, defeating image-based spam filters.

### 🔍 Comprehensive Parsing

- **Advanced Format Support**: Native processing of `.eml`, `.msg` (Outlook), `.txt`, and `.eml.gz` archives.
- **Deep Content Extraction**: recursively parses multipart messages, extracts hidden headers, analyzes HTML/Text payloads, and isolates attachments.

## 📦 Installation

### Prerequisites

- Python 3.8+
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) (Required for image analysis)
  - Windows: [Installer](https://github.com/UB-Mannheim/tesseract/wiki)
  - Linux: `sudo apt install tesseract-ocr`
  - macOS: `brew install tesseract`

### Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/phishing-email-analyzer.git
   cd phishing-email-analyzer
   ```

2. **Install core dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**
   Create a `.env` file in the root directory with your API keys:

   ```ini
   # Essential for AI Analysis
   GEMINI_API_KEY=your_gemini_key

   # Essential for External Threat Checks
   VIRUSTOTAL_API_KEY=your_vt_key
   SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
   PHISHTANK_API_KEY=your_phishtank_key (Optional)
   ```

## 💻 Usage

### Command Line Interface

**Analyze a single email:**

```bash
python main.py -f suspicious_email.msg
```

**Generate a detailed HTML report:**

```bash
python main.py -f invoice.eml --format html -o analysis_report.html
```

**Bulk scan a directory:**

```bash
python main.py -d ./investigations/ --format json -o batch_results.json
```

### Python API

Integrate the analyzer into your own security pipelines:

```python
from src.analyzer import EmailAnalyzer

# Initialize with all advanced engines (ML, OCR, Auth, etc.)
analyzer = EmailAnalyzer()

# Run deep analysis
result = analyzer.analyze_email("path/to/suspected_phish.msg")

if result['risk_level'] == 'CRITICAL':
    print(f"🚨 Blocked: {result['phishing_suspicion_score']}/100")
    print(f"Findings: {result['findings']}")
else:
    print("✅ Email appears safe")
```

## 📊 Detection Logic

The system employs a multi-layered approach to calculate risk:

1.  **Transport Layer**: Checks SPF, DKIM, and DMARC alignment.
2.  **Static Heuristics**: 8+ rule-based checks for obfuscation, typosquatting, and anomalies.
3.  **Threat Intel**: Queries external databases for known malicious indicators.
4.  **Content Analysis**:
    - **ML**: Statistical probability based on feature vectors.
    - **OCR**: Text extraction from images.
    - **LLM**: Contextual understanding of intent and urgency.

## 🛠️ Architecture

The tool is built on a modular architecture to allow easy extension:

- `src/auth_validator.py`: Handles active DNS and crypto verification.
- `src/ml_analyzer.py`: Manages local scikit-learn models.
- `src/image_analyzer.py`: Interface for Tesseract OCR.
- `src/external_scanners.py`: API wrappers for Safe Browsing/PhishTank.
- `src/analyzer.py`: The central orchestrator fusing all signals.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

_Built for security researchers and SOC analysts._

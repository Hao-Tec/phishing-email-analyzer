# Email Phishing Detection Tool

A comprehensive, modular Python tool for analyzing emails to detect phishing attacks. The tool extracts key email information, evaluates suspicious patterns using multiple heuristics, and generates detailed reports with risk scoring.

![CI](https://github.com/Hao-Tec/phishing-email-analyzer/actions/workflows/ci.yml/badge.svg)

## Features

### Core Functionality
- **Email Parsing**: Supports raw and EML-format emails
- **Metadata Extraction**: Extracts sender, recipient, subject, headers, URLs, and attachments
- **Multi-Heuristic Analysis**: 8 different detection heuristics for comprehensive phishing detection
- **Risk Scoring**: Calculates phishing suspicion score (0-100) with risk level classification
- **Detailed Reporting**: Generates human-readable text and JSON reports

### Detection Heuristics

1. **Sender Domain Mismatch**: Identifies suspicious domain patterns in sender address
2. **URL Domain Mismatch**: Detects mismatches between displayed URL text and actual link destination
3. **URL Obfuscation**: Detects shortened URLs, hex-encoded characters, and excessive subdomains
4. **Suspicious Attachments**: Identifies dangerous file extensions and double extensions
5. **Header Anomalies**: Detects missing headers and Reply-To address mismatches
6. **Urgent Language**: Identifies urgency/threatening keywords commonly used in phishing
7. **Suspicious TLDs**: Flags known malicious top-level domains
8. **IP-Based URLs**: Detects URLs using IP addresses instead of domain names

### Modularity & Extensibility

The tool is designed with a modular architecture for easy extension:

```
src/
├── config.py          # Configurable thresholds and heuristic weights
├── email_parser.py    # Email parsing module
├── heuristics.py      # Detection heuristics
├── analyzer.py        # Orchestrator module
└── reporter.py        # Report generation
```

Each module can be independently updated or extended without affecting others.

## Installation

### Prerequisites
- Python 3.7+
- pip

### Setup

1. Clone or download the project
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command-Line Interface

#### Analyze a Single Email
```bash
python main.py -f path/to/email.eml
```

#### Save Report to File
```bash
python main.py -f path/to/email.eml -o report.txt
```

#### JSON Output
```bash
python main.py -f path/to/email.eml --format json -o report.json
```

#### Batch Analysis
```bash
python main.py -d path/to/email/folder/
```

#### Batch Analysis with Summary Report
```bash
python main.py -d path/to/email/folder/ -o summary_report.txt
```

### Usage as a Library

```python
from src.analyzer import EmailAnalyzer
from src.reporter import EmailReporter

# Analyze single email
analyzer = EmailAnalyzer()
result = analyzer.analyze_email("path/to/email.eml")

# Generate report
report = EmailReporter.generate_text_report(result)
print(report)

# Save report
EmailReporter.save_report(report, "output.txt")

# Batch analysis
results = analyzer.analyze_batch("path/to/email/folder/")
summary = EmailReporter.generate_summary_report(results)
```

## Report Format

### Text Report Includes
- Email metadata (From, To, Subject, Date, Format)
- Phishing risk assessment with score and level
- Detailed findings grouped by severity
- Extracted URLs and attachments
- Risk-based recommendations

### Risk Levels
- **SAFE** (0-29): No suspicious patterns detected
- **LOW_RISK** (30-59): Minor suspicious indicators
- **MEDIUM_RISK** (60-84): Moderate phishing indicators
- **HIGH_RISK** (85-99): Highly suspicious email
- **CRITICAL** (100): Critical phishing threat

## Configuration

Edit `src/config.py` to customize:
- Heuristic weights (importance of each detection method)
- Risk thresholds (score cutoffs for risk levels)
- Suspicious file extensions
- Urgent keywords list
- Suspicious TLDs
- URL length thresholds

## Sample Data

The `samples/` directory contains test emails:
- `phishing_email_1.eml`: Bank phishing attempt with IP-based URL and shortened link
- `phishing_email_2.eml`: PayPal typosquatting with suspicious attachment
- `phishing_email_3.eml`: Prize scam with URL mismatch and suspicious TLD
- `legitimate_email_1.eml`: Normal business communication
- `legitimate_email_2.eml`: GitHub security notification

Test the tool:
```bash
python main.py -f samples/phishing_email_1.eml
python main.py -d samples/ -o batch_report.txt
```

## Architecture

### Module Responsibilities

**config.py**
- Centralized configuration
- Heuristic weights
- Risk thresholds
- Pattern definitions

**email_parser.py (EmailParser)**
- Parses EML and raw email formats
- Extracts metadata
- Extracts URLs with context
- Extracts attachments
- Detects HTML vs plain text

**heuristics.py (PhishingHeuristics)**
- Implements 8 detection heuristics
- Calculates weighted phishing score
- Generates detailed findings
- Assesses severity levels

**analyzer.py (EmailAnalyzer)**
- Orchestrates parsing and heuristics
- Coordinates workflow
- Determines risk level
- Supports single and batch analysis

**reporter.py (EmailReporter)**
- Generates text reports
- Generates JSON reports
- Generates batch summaries
- Saves reports to files
- Provides risk-based recommendations

## Extending the Tool

### Adding a New Heuristic

1. Add heuristic weight to `src/config.py`:
   ```python
   HEURISTIC_WEIGHTS = {
       "new_heuristic": 15,  # weight out of 100
       ...
   }
   ```

2. Add detection method to `src/heuristics.py`:
   ```python
   def _check_new_heuristic(self, email_data: Dict):
       """Detect pattern"""
       if suspicious_pattern:
           self._add_finding(
               "new_heuristic",
               "HIGH",  # or "MEDIUM", "LOW"
               "Description of finding",
               {"detail": "value"}
           )
   ```

3. Call the method in the `evaluate()` function:
   ```python
   def evaluate(self, email_data: Dict):
       ...
       self._check_new_heuristic(email_data)
       ...
   ```

### Integrating with Other Security Tools

The modular structure makes integration straightforward:

```python
from src.analyzer import EmailAnalyzer

# Analyze email
analyzer = EmailAnalyzer()
result = analyzer.analyze_email("email.eml")

# Extract results for integration
score = result["phishing_suspicion_score"]
risk_level = result["risk_level"]
findings = result["findings"]

# Send to external API, log, alert, etc.
if score > 80:
    send_to_security_team(result)
```

## Limitations & Future Enhancements

### Current Limitations
- No DKIM/SPF/DMARC verification
- No external phishing database lookups
- No machine learning model integration
- No image analysis or OCR
- Limited to textual heuristics

### Possible Enhancements
- Integration with VirusTotal API for attachment analysis
- DKIM/SPF signature verification
- Machine learning model for pattern recognition
- Phishing database integration (PhishTank, Google Safe Browsing)
- Image-based detection for embedded credentials
- Language model analysis for social engineering
- Support for additional email formats (.msg, .eml.gz)

## Error Handling

The tool gracefully handles:
- Invalid file paths
- Corrupted email files
- Missing headers
- Encoding errors
- Malformed URLs

## License

This project is provided as-is for security research and email security purposes.

## Disclaimer

This tool is designed to assist in phishing detection but should not be the sole arbiter of email safety. Always combine automated tools with user training and multi-layered security strategies.

## Support & Development

For bug reports, feature requests, or contributions, please refer to the project documentation.

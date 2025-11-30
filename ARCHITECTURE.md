# Email Phishing Detection Tool - Architecture & Extension Guide

## Project Structure

```
Lockin/
├── main.py                 # CLI entry point
├── quickstart.py           # Quick start guide script
├── requirements.txt        # Python dependencies
├── README.md               # User documentation
├── ARCHITECTURE.md         # This file
│
├── src/                    # Main package
│   ├── __init__.py
│   ├── config.py           # Centralized configuration
│   ├── email_parser.py     # Email parsing module
│   ├── heuristics.py       # Phishing detection heuristics
│   ├── analyzer.py         # Orchestrator module
│   └── reporter.py         # Report generation
│
├── tests/                  # Test suite
│   ├── __init__.py
│   └── test_phishing_detector.py
│
└── samples/                # Sample test emails
    ├── phishing_email_1.eml
    ├── phishing_email_2.eml
    ├── phishing_email_3.eml
    ├── legitimate_email_1.eml
    └── legitimate_email_2.eml
```

## Module Responsibilities

### config.py
**Purpose**: Centralized configuration management

**Key Components**:
- `SCORE_THRESHOLD`: Risk level thresholds
- `HEURISTIC_WEIGHTS`: Importance of each heuristic
- `SUSPICIOUS_EXTENSIONS`: File extensions to flag
- `SUSPICIOUS_TLDS`: Malicious top-level domains
- `URGENT_KEYWORDS`: Words commonly in phishing emails

**Extensibility**: Modify thresholds and weights without changing logic

### email_parser.py - EmailParser Class

**Purpose**: Extract structured data from email files

**Key Methods**:
- `parse_email(path)`: Parse EML file
- `parse_email_from_string(string)`: Parse email string
- `_extract_sender()`: Get sender email address
- `_extract_urls()`: Find all URLs in email
- `_extract_attachments()`: Get attachment metadata
- `_extract_headers()`: Parse email headers

**Output Format**:
```python
{
    "sender": "user@example.com",
    "recipient": "other@example.com",
    "subject": "Email Subject",
    "date": "Date string",
    "headers": {dict of all headers},
    "body": "Full email body text",
    "urls": [
        {
            "url": "https://example.com",
            "domain": "example.com",
            "displayed_text": "Click here"  # if different from URL
        }
    ],
    "attachments": [
        {
            "filename": "document.pdf",
            "size": 1024,
            "content_type": "application/pdf"
        }
    ],
    "is_html": False,
    "reply_to": ""
}
```

**Extending**:
- Add new extraction methods for additional metadata
- Modify URL detection regex patterns
- Support additional email formats (.msg, .eml.gz)

### heuristics.py - PhishingHeuristics Class

**Purpose**: Implement detection heuristics and calculate risk score

**Current Heuristics**:
1. `_check_sender_domain_mismatch()`: Validates sender domain patterns
2. `_check_url_domain_mismatch()`: Detects link text/URL mismatches
3. `_check_url_obfuscation()`: Finds shortened/hex-encoded URLs
4. `_check_suspicious_attachments()`: Flags dangerous files
5. `_check_header_anomalies()`: Finds header inconsistencies
6. `_check_urgent_language()`: Detects urgency keywords
7. `_check_suspicious_tlds()`: Flags known-bad domains
8. `_check_ip_based_urls()`: Finds IP-based URL links

**Scoring System**:
- Each heuristic has a base weight (0-100)
- Severity multiplier (LOW: 0.5x, MEDIUM: 1.0x, HIGH: 1.5x)
- Final score = sum of all adjusted weights, capped at 100

**Method Signature**:
```python
def evaluate(email_data: Dict) -> Tuple[int, List[Dict]]:
    # Returns (score, findings)
    # findings = [
    #     {
    #         "heuristic": "name",
    #         "severity": "HIGH|MEDIUM|LOW",
    #         "description": "human readable",
    #         "weight": 20,
    #         "adjusted_weight": 30.0,
    #         "details": {...}
    #     }
    # ]
```

**Extending**:
1. Add new detection method
2. Add weight to `config.HEURISTIC_WEIGHTS`
3. Call new method in `evaluate()`
4. Use `_add_finding()` to record results

### analyzer.py - EmailAnalyzer Class

**Purpose**: Orchestrate parsing and heuristics evaluation

**Key Methods**:
- `analyze_email(path)`: Analyze single email file
- `analyze_email_from_string(content)`: Analyze email string
- `analyze_batch(folder)`: Analyze all emails in folder
- `_determine_risk_level(score)`: Map score to risk level

**Output Format**:
```python
{
    "status": "success|error",
    "file": "path/to/email.eml",
    "email_metadata": {...},
    "phishing_suspicion_score": 75.5,
    "risk_level": "HIGH_RISK",
    "findings": [...],
    "urls_detected": 3,
    "attachments_detected": 1,
    "extracted_data": {
        "urls": [...],
        "attachments": [...]
    }
}
```

**Extensibility**:
- Add pre/post-processing hooks
- Integrate with external services
- Modify risk level thresholds
- Chain additional analyzers

### reporter.py - EmailReporter Class

**Purpose**: Format analysis results into reports

**Key Methods**:
- `generate_text_report(result)`: Human-readable text format
- `generate_json_report(result)`: Machine-readable JSON
- `generate_summary_report(results)`: Batch summary
- `save_report(content, path)`: Write report to file

**Report Sections**:
- Email metadata
- Risk assessment with score and level
- Detailed findings by severity
- Extracted URLs and attachments
- Risk-based recommendations

**Extensibility**:
- Create new report formats (HTML, PDF, CSV)
- Customize recommendation logic
- Add chart generation
- Integrate with ticketing systems

## Data Flow

```
Email File
    ↓
EmailParser.parse_email()
    ↓
Raw Email Data Dict
    ↓
PhishingHeuristics.evaluate()
    ↓
Score + Findings
    ↓
EmailAnalyzer (orchestrates above)
    ↓
Analysis Result Dict
    ↓
EmailReporter (formats output)
    ↓
Text/JSON Report
```

## Extension Patterns

### Adding a New Detection Heuristic

**Step 1**: Add weight to config.py
```python
HEURISTIC_WEIGHTS = {
    "new_detection": 18,  # out of 100
}
```

**Step 2**: Implement detection method in heuristics.py
```python
def _check_new_detection(self, email_data: Dict):
    """Detect a new phishing pattern."""
    pattern_found = False
    
    if pattern_found:
        self._add_finding(
            "new_detection",
            "HIGH",  # or MEDIUM, LOW
            "Description of what was detected",
            {"detail1": "value", "detail2": "value"}
        )
```

**Step 3**: Call in evaluate()
```python
def evaluate(self, email_data: Dict) -> Tuple[int, List[Dict]]:
    # ... existing calls ...
    self._check_new_detection(email_data)
    return self.score, self.findings
```

### Integrating with External Services

**Pattern**: Wrap in adapter method
```python
def analyze_with_virustotal(self, urls: List[str]) -> List[Dict]:
    """Check URLs against VirusTotal API."""
    results = []
    for url in urls:
        response = requests.get(f"https://www.virustotal.com/api/v3/...", 
                                headers=self.vt_headers)
        if response.status_code == 200:
            results.append({
                "url": url,
                "detection_count": response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
            })
    return results
```

Then call from analyzer:
```python
vt_results = analyzer.analyze_with_virustotal(email_data["urls"])
for result in vt_results:
    if result["detection_count"] > 5:
        # Flag as phishing
```

### Custom Report Format

Create new method in reporter.py:
```python
@staticmethod
def generate_html_report(analysis_result: Dict) -> str:
    """Generate an HTML report."""
    html = """
    <html>
    <head><title>Phishing Analysis Report</title></head>
    <body>
    <h1>Email Analysis</h1>
    <!-- Format results as HTML -->
    </body>
    </html>
    """
    return html
```

## Testing Strategy

**Unit Tests** (test_phishing_detector.py):
- Parser: Email extraction accuracy
- Heuristics: Individual detection logic
- Analyzer: Orchestration and scoring
- Integration: Full pipeline

**Sample Emails**:
- phishing_email_*.eml: Known phishing patterns
- legitimate_email_*.eml: False positive checking

**Running Tests**:
```bash
python -m unittest tests.test_phishing_detector -v
```

## Performance Considerations

- **Email Size**: Large attachments may slow parsing
- **URL Extraction**: Regex patterns can be expensive
- **Batch Processing**: Process in parallel for better performance
- **Score Calculation**: Linear calculation, O(n) where n = number of heuristics

## Security Considerations

- **Code Injection**: Email parser sanitizes headers
- **File Access**: Validates paths before opening
- **Third-party APIs**: Use authentication tokens
- **Sensitive Data**: Consider PII in email content

## Future Enhancement Opportunities

1. **Machine Learning Integration**
   - Train model on known phishing/legitimate emails
   - Use ML for pattern recognition
   - Reduce false positives

2. **External Services**
   - Google Safe Browsing API
   - PhishTank database integration
   - DKIM/SPF/DMARC verification
   - VirusTotal attachment scanning

3. **Advanced Analysis**
   - Image-based detection for embedded credentials
   - Language model analysis for social engineering
   - Sender reputation checking
   - Behavioral analysis

4. **Format Support**
   - Microsoft Outlook .msg format
   - Compressed email archives
   - MBOX format for email clients

5. **Reporting**
   - HTML/PDF report generation
   - Dashboard with metrics
   - Alert integration
   - SIEM integration

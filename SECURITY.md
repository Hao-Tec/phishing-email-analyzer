# Security Policy

## Supported Versions

We are committed to the security of the Phishing Email Analyzer. Currently, we support the latest major version with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Data Privacy & URL Scraping

This tool includes a **Real-Time URL Analysis** feature that fetches content from links found in emails.

- **Purpose**: To detect phishing pages that use valid domains but host malicious forms.
- **Workflow**: The tool makes a standard HTTP GET request to the URL and sends the extracted text to the configured LLM (e.g., Google Gemini) for analysis.
- **Privacy Warning**: If you analyze emails containing sensitive private links (e.g., password reset tokens), the content of those pages will be sent to the LLM provider.
- **Mitigation**: Use the tool in a controlled environment. You can disable this feature by modifying `src/config.py` or running the tool with a flag (future feature).

## Reporting a Vulnerability

We request that you **do not** start a public issue for security vulnerabilities. This gives us time to patch the issue before it can be exploited.

### How to Report

Please report sensitive security issues via one of the following methods:

1.  **GitHub Security Advisories**: If enabled, use the "Report a vulnerability" button in the **Security** tab of this repository.
2.  **Email**: Contact the maintainer at `haotec.reports@gmail.com`.

### What to Include

- Description of the vulnerability.
- Steps to reproduce the issue.
- Potential impact.

### Our Process

1.  **Acknowledgment**: We will respond to your report within 48 hours.
2.  **Assessment**: We will investigate the issue and determine its severity.
3.  **Fix**: We will work on a patch and release it as soon as possible.
4.  **Disclosure**: Once fixed, we will publish a security advisory detailing the vulnerability and the fix.

Thank you for helping make this project safer!

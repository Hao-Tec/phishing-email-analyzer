"""
Reporter Module
Formats analysis results into clear, human-readable reports.
"""

import json
from typing import Dict, List
from datetime import datetime
from pathlib import Path


class EmailReporter:
    """
    Generate formatted reports of phishing analysis results.
    """

    @staticmethod
    def generate_text_report(analysis_result: Dict) -> str:
        """
        Generate a plain text report.

        Args:
            analysis_result: Analysis result from EmailAnalyzer

        Returns:
            Formatted text report
        """
        if analysis_result.get("status") == "error":
            return EmailReporter._format_error_report(analysis_result)

        report = []
        report.append("=" * 80)
        report.append("EMAIL PHISHING ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")

        # Timestamp
        report.append(
            f"Analysis Date: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"  # noqa: E501
        )
        report.append("")

        # Email metadata
        metadata = analysis_result.get("email_metadata", {})
        report.append("EMAIL METADATA")
        report.append("-" * 80)
        report.append(f"From:      {metadata.get('sender', 'N/A')}")
        report.append(f"To:        {metadata.get('recipient', 'N/A')}")
        report.append(f"Subject:   {metadata.get('subject', 'N/A')}")
        report.append(f"Date:      {metadata.get('date', 'N/A')}")
        is_html = "HTML" if metadata.get("is_html") else "Plain Text"
        report.append(f"Format:    {is_html}")
        report.append("")

        # Risk assessment
        report.append("PHISHING RISK ASSESSMENT")
        report.append("-" * 80)
        score = analysis_result.get("phishing_suspicion_score", 0)
        risk_level = analysis_result.get("risk_level", "UNKNOWN")

        # Color-coded risk level (text representation)
        risk_indicators = {
            "SAFE": "[✓ SAFE]",
            "LOW_RISK": "[⚠ LOW RISK]",
            "MEDIUM_RISK": "[⚠⚠ MEDIUM RISK]",
            "HIGH_RISK": "[⚠⚠⚠ HIGH RISK]",
            "CRITICAL": "[✗ CRITICAL]",
        }

        report.append(
            f"Risk Level:           "
            f"{risk_indicators.get(risk_level, risk_level)}"  # noqa: E501
        )
        report.append(f"Suspicion Score:      {score:.1f}/100")
        report.append("")

        # Detected elements
        report.append("DETECTED ELEMENTS")
        report.append("-" * 80)
        report.append(
            f"URLs Found:           "
            f"{analysis_result.get('urls_detected', 0)}"
        )
        report.append(
            f"Attachments Found:    "
            f"{analysis_result.get('attachments_detected', 0)}"
        )
        report.append("")

        # Detailed findings
        findings = analysis_result.get("findings", [])
        if findings:
            report.append("FINDINGS")
            report.append("-" * 80)

            # Group findings by severity
            by_severity = {"HIGH": [], "MEDIUM": [], "LOW": []}
            for finding in findings:
                severity = finding.get("severity", "LOW")
                if severity in by_severity:
                    by_severity[severity].append(finding)

            # Report HIGH severity first
            for severity_order in ["HIGH", "MEDIUM", "LOW"]:
                severity_findings = by_severity[severity_order]
                if severity_findings:
                    report.append(f"\n{severity_order} SEVERITY FINDINGS:")
                    for i, finding in enumerate(severity_findings, 1):
                        heur = finding.get("heuristic", "Unknown")
                        report.append(f"\n  {i}. [{heur}]")
                        desc = finding.get("description", "N/A")
                        report.append(f"     Desc: {desc}")
                        if finding.get("details"):
                            details = finding.get("details", {})
                            for k, v in details.items():
                                v_str = str(v)
                                if isinstance(v, str) and len(v) > 60:
                                    report.append(f"     {k}: {v_str[:40]}...")
                                else:
                                    report.append(f"     {k}: {v_str}")
        else:
            report.append("FINDINGS")
            report.append("-" * 80)
            report.append("No suspicious patterns detected.")

        report.append("")

        # Extracted data
        extracted_data = analysis_result.get("extracted_data", {})
        urls = extracted_data.get("urls", [])
        attachments = extracted_data.get("attachments", [])

        if urls:
            report.append("EXTRACTED URLs")
            report.append("-" * 80)
            for i, url_obj in enumerate(urls, 1):
                report.append(f"{i}. {url_obj.get('url', 'N/A')}")
                report.append(f"   Domain: {url_obj.get('domain', 'N/A')}")
                if url_obj.get("displayed_text"):
                    report.append(
                        f"   Displayed Text: "
                        f"{url_obj.get('displayed_text', 'N/A')}"
                    )
            report.append("")

        if attachments:
            report.append("EXTRACTED ATTACHMENTS")
            report.append("-" * 80)
            for i, attachment in enumerate(attachments, 1):
                report.append(
                    f"{i}. {attachment.get('filename', 'N/A')}"
                )
                report.append(
                    f"   Type: {attachment.get('content_type', 'N/A')}"
                )
                report.append(
                    f"   Size: {attachment.get('size', 0)} bytes"
                )
            report.append("")

        # Recommendations
        report.append("RECOMMENDATIONS")
        report.append("-" * 80)
        recommendations = EmailReporter._get_recommendations(
            risk_level, findings
        )
        for i, rec in enumerate(recommendations, 1):
            report.append(f"• {rec}")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    @staticmethod
    def generate_json_report(analysis_result: Dict) -> str:
        """
        Generate a JSON report.

        Args:
            analysis_result: Analysis result from EmailAnalyzer

        Returns:
            JSON formatted report
        """
        # Add metadata
        output = {
            "generated_at": datetime.now().isoformat(),
            "analysis": analysis_result,
        }

        return json.dumps(output, indent=2, default=str)

    @staticmethod
    def generate_html_report(analysis_result: Dict) -> str:
        """
        Generate a stylish HTML report.

        Args:
            analysis_result: Analysis result from EmailAnalyzer

        Returns:
            HTML formatted report
        """
        metadata = analysis_result.get("email_metadata", {})
        score = analysis_result.get("phishing_suspicion_score", 0)
        risk_level = analysis_result.get("risk_level", "UNKNOWN")
        findings = analysis_result.get("findings", [])

        # Color coding
        colors = {
            "SAFE": "#28a745",
            "LOW_RISK": "#17a2b8",
            "MEDIUM_RISK": "#ffc107",
            "HIGH_RISK": "#fd7e14",
            "CRITICAL": "#dc3545",
        }
        risk_color = colors.get(risk_level, "#6c757d")

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">
            <title>Phishing Analysis Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana,
                    sans-serif;
                    background-color: #f8f9fa;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 900px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .header {{
                    border-bottom: 2px solid #eee;
                    padding-bottom: 20px;
                    margin-bottom: 20px;
                }}
                .badge {{
                    display: inline-block;
                    padding: 8px 16px;
                    border-radius: 20px;
                    color: white;
                    font-weight: bold;
                    font-size: 1.2em;
                    background-color: {risk_color};
                }}
                .score {{
                    font-size: 2.5em;
                    font-weight: bold;
                    color: {risk_color};
                    margin: 10px 0;
                }}
                .section {{ margin-bottom: 30px; }}
                h2 {{
                    color: #343a40;
                    border-left: 5px solid {risk_color};
                    padding-left: 10px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #dee2e6;
                }}
                th {{ background-color: #f8f9fa; color: #495057; }}
                .finding {{
                    background-color: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 15px;
                    margin-bottom: 15px;
                }}
                .finding.HIGH {{
                    background-color: #f8d7da;
                    border-left-color: #dc3545;
                }}
                .finding.LOW {{
                    background-color: #d1e7dd;
                    border-left-color: #198754;
                }}
                .meta-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit,
                    minmax(200px, 1fr));
                    gap: 20px;
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                }}
                .meta-item label {{
                    display: block;
                    color: #6c757d;
                    font-size: 0.9em;
                }}
                .meta-item span {{
                    font-weight: 500;
                    font-size: 1.1em;
                    color: #212529;
                    word-break: break-word;
                    overflow-wrap: break-word;
                    display: block;
                }}
                .glossary-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 15px;
                }}
                .glossary-item {{
                    background: #f1f3f5;
                    padding: 15px;
                    border-radius: 8px;
                }}
                .glossary-term {{
                    font-weight: bold;
                    color: #495057;
                    display: block;
                    margin-bottom: 5px;
                }}
                .glossary-def {{
                    font-size: 0.9em;
                    color: #6c757d;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Phishing Analysis Report</h1>
                    <div class="score">{score:.1f}/100</div>
                    <div class="badge">{risk_level.replace('_', ' ')}</div>
                    <p>Generated on
                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>

                <div class="section">
                    <h2>Email Metadata</h2>
                    <div class="meta-grid">
                        <div class="meta-item">
                            <label>From</label>
                            <span>{metadata.get('sender', 'N/A')}</span>
                        </div>
                        <div class="meta-item">
                            <label>To</label>
                            <span>{metadata.get('recipient', 'N/A')}</span>
                        </div>
                        <div class="meta-item">
                            <label>Subject</label>
                            <span>{metadata.get('subject', 'N/A')}</span>
                        </div>
                        <div class="meta-item">
                            <label>Date</label>
                            <span>{metadata.get('date', 'N/A')}</span>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <h2>Findings</h2>
                    {'<p>No suspicious patterns detected.</p>'
                     if not findings else ''}
        """

        # Group findings by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        other_severities = {}
        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in by_severity:
                by_severity[severity].append(finding)
            else:
                if severity not in other_severities:
                    other_severities[severity] = []
                other_severities[severity].append(finding)

        # Icons for severity
        icons = {
            "CRITICAL": "🚫",
            "HIGH": "🔴",
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "INFO": "🔵",
            "SAFE": "🟢"
        }

        # Helper function to generate finding HTML
        def generate_finding_html(severity, finding):
            sev_icon = icons.get(severity, "⚪")
            finding_html = f"""
                    <div class="finding {severity}">
                        <strong>{sev_icon} [{severity}]
                        {finding.get('heuristic', 'Unknown')}</strong>
                        <p>{finding.get('description', '')}</p>
            """
            if finding.get("details"):
                finding_html += "<ul>"
                for k, v in finding.get("details", {}).items():
                    finding_html += f"<li>{k}: {v}</li>"
                finding_html += "</ul>"
            finding_html += "</div>"
            return finding_html

        # Display findings sorted by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            for finding in by_severity.get(severity, []):
                html += generate_finding_html(severity, finding)

        # Display any other severities
        for severity, severity_findings in other_severities.items():
            for finding in severity_findings:
                html += generate_finding_html(severity, finding)

        html += """
                </div>

                <div class="section">
                    <h2>Glossary</h2>
                    <div class="glossary-grid">
        """

        glossary = {
            "SPF": "Sender Policy Framework. A security mechanism that allows domains to specify which mail servers are authorized to send email on their behalf.",
            "DKIM": "DomainKeys Identified Mail. Adds a digital signature to emails, allowing the receiver to verify that the email was indeed authorized by the owner of that domain.",
            "DMARC": "Domain-based Message Authentication, Reporting, and Conformance. Unifies SPF and DKIM mechanisms and tells receivers what to do if checks fail.",
            "Doppelganger Domain": "A domain that looks very similar to a legitimate domain (e.g., paypa1.com vs paypal.com) to trick users.",
            "Typosquatting": "Registering domains that are very similar to popular domains, relying on users making typos.",
            "Homograph Attack": "Using characters that look alike (e.g., Cyrillic 'a' vs Latin 'a') to spoof domains.",
            "Zero-Day": "A newly discovered vulnerability or threat that has no known fix or signature yet.",
            "ML Confidence": "The probability score (0-1) from the Machine Learning model indicating how likely the email is phishing.",
        }

        for term, definition in glossary.items():
            html += f"""
                        <div class="glossary-item">
                            <span class="glossary-term">{term}</span>
                            <span class="glossary-def">{definition}</span>
                        </div>
            """

        html += """
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        return html

    @staticmethod
    def generate_summary_report(batch_results: List[Dict]) -> str:
        """
        Generate a summary report for batch analysis.

        Args:
            batch_results: List of analysis results

        Returns:
            Formatted summary report
        """
        report = []
        report.append("=" * 80)
        report.append("BATCH EMAIL ANALYSIS SUMMARY REPORT")
        report.append("=" * 80)
        report.append("")

        report.append(
            f"Analysis Date: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"  # noqa: E501
        )
        report.append(f"Total Emails Analyzed: {len(batch_results)}")
        report.append("")

        # Count by risk level
        risk_counts = {
            "SAFE": 0,
            "LOW_RISK": 0,
            "MEDIUM_RISK": 0,
            "HIGH_RISK": 0,
            "CRITICAL": 0,
            "ERROR": 0,
        }

        for result in batch_results:
            if result.get("status") == "error":
                risk_counts["ERROR"] += 1
            else:
                risk_level = result.get("risk_level", "UNKNOWN")
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1

        report.append("RISK DISTRIBUTION")
        report.append("-" * 80)
        report.append(f"SAFE (0-29):         {risk_counts['SAFE']} emails")
        report.append(f"LOW_RISK (30-59):    {risk_counts['LOW_RISK']} emails")
        report.append(
            f"MEDIUM_RISK (60-84): {risk_counts.get('MEDIUM_RISK')} "
            f"emails"
        )
        report.append(
            f"HIGH_RISK (85-99):   {risk_counts.get('HIGH_RISK')} "
            f"emails"
        )
        report.append(f"CRITICAL (100):      {risk_counts['CRITICAL']} emails")
        report.append(f"ERRORS:              {risk_counts['ERROR']} emails")
        report.append("")

        # Detailed results
        report.append("DETAILED RESULTS")
        report.append("-" * 80)

        for i, result in enumerate(batch_results, 1):
            if result.get("status") == "error":
                report.append(
                    f"{i}. {result.get('file', 'Unknown')} - "
                    f"ERROR: {result.get('error', 'Unknown error')}"
                )
            else:
                file_path = Path(result.get("file", "")).name
                score = result.get("phishing_suspicion_score", 0)
                risk_level = result.get("risk_level", "UNKNOWN")
                subject = (
                    result.get("email_metadata", {})
                    .get("subject", "N/A")[:50]
                )

                report.append(f"{i}. {file_path}")
                report.append(f"   Subject: {subject}")
                report.append(f"   Risk: {risk_level} ({score:.1f}/100)")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    @staticmethod
    def save_report(report_content: str, output_path: str):
        """
        Save report to file.

        Args:
            report_content: Report content
            output_path: Path to save report
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report_content)

    @staticmethod
    def _format_error_report(error_result: Dict) -> str:
        """Format error report."""
        report = []
        report.append("=" * 80)
        report.append("EMAIL ANALYSIS ERROR REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(
            "File: " + str(error_result.get("file", "Unknown"))
        )
        report.append(
            "Error: " + str(error_result.get("error", "Unknown error"))
        )
        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    @staticmethod
    def _get_recommendations(
        risk_level: str, findings: List[Dict]
    ) -> List[str]:
        """
        Generate recommendations based on risk level and findings.

        Args:
            risk_level: Risk level classification
            findings: List of findings

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if risk_level == "SAFE":
            recommendations.append(
                "Email appears to be legitimate. No action required."
            )

        elif risk_level == "LOW_RISK":
            recommendations.append(
                "Minor phishing indicators. Exercise normal caution."
            )
            recommendations.append(
                "Do not click links unless you verify the sender "
                "independently."
            )

        elif risk_level == "MEDIUM_RISK":
            recommendations.append(
                "Email shows moderate phishing indicators. "
                "Exercise heightened caution."
            )
            recommendations.append(
                "Do NOT click links or download attachments from "
                "this email."
            )
            recommendations.append(
                "Verify any requests directly with the sender using "
                "known contact information."
            )

        elif risk_level == "HIGH_RISK":
            recommendations.append(
                "Email is highly suspicious and likely malicious."
            )
            recommendations.append(
                "DO NOT interact with any links, attachments, or "
                "requests in this email."
            )
            recommendations.append(
                "Report this email to your IT security team or "
                "email provider."
            )
            recommendations.append(
                "Delete the email immediately if possible."
            )

        elif risk_level == "CRITICAL":
            recommendations.append("ALERT: Email is critical phishing threat.")
            recommendations.append(
                "DO NOT open attachments or click any links."
            )
            recommendations.append(
                "IMMEDIATELY report to your IT security team."
            )
            recommendations.append(
                "Do not reply or forward this email."
            )
            recommendations.append(
                "Consider blocking the sender's email address."
            )

        # Add specific recommendations based on findings
        high_severity_findings = [
            f for f in findings if f.get("severity") == "HIGH"
        ]
        if any(
            f.get("heuristic") == "suspicious_attachment"
            for f in high_severity_findings
        ):
            recommendations.append(
                "This email contains potentially dangerous file "
                "attachments."
            )

        if any(
            f.get("heuristic") == "url_mismatch_with_text"
            for f in high_severity_findings
        ):
            recommendations.append(
                "This email contains deceptive links that "
                "don't match their displayed text."
            )

        return recommendations

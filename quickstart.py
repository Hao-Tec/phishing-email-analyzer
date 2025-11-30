#!/usr/bin/env python
"""
Quick start guide for Email Phishing Detection Tool
Run this script to understand the basic usage
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.analyzer import EmailAnalyzer
from src.reporter import EmailReporter

def main():
    """Demonstrate basic usage of the phishing detection tool."""

    print("=" * 80)
    print("EMAIL PHISHING DETECTION TOOL - QUICK START GUIDE")
    print("=" * 80)
    print()

    # Example 1: Analyze a single email
    print("EXAMPLE 1: Analyzing a single email")
    print("-" * 80)

    analyzer = EmailAnalyzer()

    # Try to analyze a sample email
    sample_files = list(Path("samples").glob("*.eml"))
    if sample_files:
        sample_file = sample_files[0]
        print(f"Analyzing: {sample_file.name}\n")

        result = analyzer.analyze_email(str(sample_file))

        if result.get("status") == "success":
            print(f"Risk Level: {result.get('risk_level')}")
            print(f"Suspicion Score: {result.get('phishing_suspicion_score')}/100")
            print(f"Findings: {len(result.get('findings', []))} issues detected")
            print()

    # Example 2: Generate formatted report
    print("EXAMPLE 2: Generating a text report")
    print("-" * 80)

    if result.get("status") == "success":
        # For brevity, just show a snippet
        report = EmailReporter.generate_text_report(result)
        lines = report.split('\n')
        print('\n'.join(lines[5:20]))  # Show relevant section
        print("\n[... full report continues ...]\n")

    # Example 3: Batch analysis
    print("EXAMPLE 3: Batch analyzing multiple emails")
    print("-" * 80)

    if Path("samples").exists():
        results = analyzer.analyze_batch("samples")
        print(f"Analyzed {len(results)} emails")

        # Show distribution
        risk_dist = {}
        for r in results:
            if r.get("status") == "success":
                risk = r.get("risk_level", "UNKNOWN")
                risk_dist[risk] = risk_dist.get(risk, 0) + 1

        print("Risk distribution:")
        for risk_level, count in sorted(risk_dist.items()):
            print(f"  {risk_level}: {count} emails")
        print()

    # Example 4: Using as library
    print("EXAMPLE 4: Using the tool programmatically")
    print("-" * 80)
    print("""
from src.analyzer import EmailAnalyzer
from src.reporter import EmailReporter

analyzer = EmailAnalyzer()

# Single email
result = analyzer.analyze_email("path/to/email.eml")
report = EmailReporter.generate_text_report(result)
print(report)

# Batch emails
results = analyzer.analyze_batch("path/to/email/folder/")
summary = EmailReporter.generate_summary_report(results)
EmailReporter.save_report(summary, "summary_report.txt")
    """)

    print("=" * 80)
    print("For more information, see README.md")
    print("=" * 80)

if __name__ == "__main__":
    main()

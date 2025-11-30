"""
Command-line interface for Email Phishing Detection Tool
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer import EmailAnalyzer
from src.reporter import EmailReporter


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Email Phishing Detection Tool - Analyze emails for phishing attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f email.eml
  python main.py -f email.eml -o report.txt
  python main.py -f email.eml -f format json
  python main.py -d /path/to/emails/
  python main.py -d /path/to/emails/ -o summary_report.txt
        """
    )

    parser.add_argument(
        "-f", "--file",
        metavar="PATH",
        help="Path to email file (EML or raw format)"
    )

    parser.add_argument(
        "-d", "--directory",
        metavar="PATH",
        help="Path to directory containing multiple email files"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Output file path (if not specified, prints to console)"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.file and not args.directory:
        parser.print_help()
        print("\nError: Please specify either --file or --directory")
        sys.exit(1)

    analyzer = EmailReporter()
    analyzer_engine = EmailAnalyzer()

    try:
        if args.file:
            # Single file analysis
            result = analyzer_engine.analyze_email(args.file)

            if args.format == "json":
                report = EmailReporter.generate_json_report(result)
            else:
                report = EmailReporter.generate_text_report(result)

            if args.output:
                EmailReporter.save_report(report, args.output)
                print(f"Report saved to: {args.output}")
            else:
                print(report)

        elif args.directory:
            # Batch analysis
            results = analyzer_engine.analyze_batch(args.directory)

            if args.format == "json":
                # Generate JSON for each result
                report = "[\n"
                for i, result in enumerate(results):
                    result_json = EmailReporter.generate_json_report(result)
                    # Remove outer wrapper
                    result_dict = result_json.strip()
                    if i < len(results) - 1:
                        report += result_dict + ",\n"
                    else:
                        report += result_dict
                report += "\n]"
            else:
                report = EmailReporter.generate_summary_report(results)

            if args.output:
                EmailReporter.save_report(report, args.output)
                print(f"Report saved to: {args.output}")
                print(f"Analyzed {len(results)} emails")
            else:
                print(report)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

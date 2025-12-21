# flake8: noqa
"""
Command-line interface for Email Phishing Detection Tool
"""

import sys
import signal

# Register Ctrl+C handler IMMEDIATELY before any heavy imports
def _graceful_exit(signum=None, frame=None):
    """Handle Ctrl+C gracefully without traceback."""
    print("\n[!] Operation cancelled by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, _graceful_exit)

# Now safe to import heavy modules
import argparse
import os
import logging
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.panel import Panel

# Suppress non-critical warnings for clean enterprise output
# Only show ERROR level messages in terminal
logging.basicConfig(level=logging.ERROR, format="%(message)s")

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer import EmailAnalyzer
from src.reporter import EmailReporter
from src.banner import print_banner

console = Console()


def main():
    """Main CLI entry point."""
    print_banner()
    parser = argparse.ArgumentParser(
        description="Email Phishing Detection Tool - Analyze emails for phishing attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f email.eml
  python main.py -f email.eml -o report.html --format html
  python main.py -d /path/to/emails/
  python main.py -d /path/to/emails/ --env-file .env
        """,
    )

    parser.add_argument(
        "-f", "--file", metavar="PATH", help="Path to email file (EML or raw format)"
    )

    parser.add_argument(
        "-d",
        "--directory",
        metavar="PATH",
        help="Path to directory containing multiple email files",
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )

    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Output file path (default console for text)",
    )

    parser.add_argument(
        "--env-file",
        metavar="PATH",
        help="Path to .env file for configuration",
        default=".env",
    )

    args = parser.parse_args()

    # Load environment variables
    load_dotenv(args.env_file)
    if not os.getenv("GEMINI_API_KEY"):
        console.print(
            "[yellow]Warning: GEMINI_API_KEY not found. Neural features will be disabled.[/yellow]"
        )

    # Validate arguments
    if not args.file and not args.directory:
        parser.print_help()
        console.print(
            "\n[bold red]Error: Please specify either --file or --directory[/bold red]"
        )
        sys.exit(1)

    analyzer_engine = EmailAnalyzer()

    try:
        if args.file:
            # Single file analysis
            with console.status(f"[bold green]Analyzing {args.file}...[/bold green]"):
                result = analyzer_engine.analyze_email(args.file)

            # Auto-detect format from output file extension if not specified
            output_format = args.format
            if args.output and output_format == "text":
                ext = Path(args.output).suffix.lower()
                if ext == ".html":
                    output_format = "html"
                elif ext == ".json":
                    output_format = "json"

            if output_format == "json":
                report = EmailReporter.generate_json_report(result)
            elif output_format == "html":
                report = EmailReporter.generate_html_report(result)
            else:
                report = EmailReporter.generate_text_report(result)

            if args.output:
                EmailReporter.save_report(report, args.output)
                console.print(
                    f"[bold green]Report saved to:[/bold green] {args.output}"
                )
            else:
                # Print rich summary to console if text format
                if args.format == "text":
                    _print_console_summary(result)
                else:
                    print(report)

        elif args.directory:
            # Batch analysis
            folder_path = Path(args.directory)
            files = [f for f in folder_path.iterdir() if f.is_file()]

            results = []
            for file_path in track(files, description="Analyzing emails..."):
                if file_path.suffix.lower() in [".eml", ".txt", ".msg"]:
                    results.append(analyzer_engine.analyze_email(str(file_path)))

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
            elif args.format == "html":
                # For batch HTML, we might just generate a summary or multiple files
                # For now let's just do text summary for CLI batch in HTML mode or error
                console.print(
                    "[yellow]Batch HTML report not fully supported, falling back to text summary for console[/yellow]"
                )
                report = EmailReporter.generate_summary_report(results)
            else:
                report = EmailReporter.generate_summary_report(results)

            if args.output:
                EmailReporter.save_report(report, args.output)
                console.print(
                    f"[bold green]Batch report saved to:[/bold green] {args.output}"
                )

            # Print table summary
            table = Table(title="Batch Analysis Results")
            table.add_column("File", style="cyan")
            table.add_column("Score", justify="right")
            table.add_column("Risk Level")
            table.add_column("Subject")

            for res in results:
                score = res.get("phishing_suspicion_score", 0)
                risk = res.get("risk_level", "UNKNOWN")
                risk_style = "green"
                if risk in ["HIGH_RISK", "CRITICAL"]:
                    risk_style = "red bold"
                elif risk == "MEDIUM_RISK":
                    risk_style = "yellow"

                table.add_row(
                    Path(res.get("file", "")).name,
                    f"{score:.1f}",
                    f"[{risk_style}]{risk}[/{risk_style}]",
                    res.get("email_metadata", {}).get("subject", "N/A")[:30] + "...",
                )

            console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


def _print_console_summary(result: dict):
    """Print a pretty summary to console."""
    score = result.get("phishing_suspicion_score", 0)
    risk = result.get("risk_level", "UNKNOWN")

    color = "green"
    if risk in ["HIGH_RISK", "CRITICAL"]:
        color = "red"
    elif risk == "MEDIUM_RISK":
        color = "yellow"

    console.print(
        Panel.fit(
            f"[bold]Phishing Analysis Result[/bold]\n\n"
            f"Score: [{color}]{score:.1f}/100[/{color}]\n"
            f"Risk:  [{color}]{risk}[/{color}]\n"
            f"Subject: {result.get('email_metadata', {}).get('subject', 'N/A')}",
            border_style=color,
        )
    )

    findings = result.get("findings", [])
    if findings:
        console.print("\n[bold]Key Findings:[/bold]")
        for f in findings:
            sev = f.get("severity", "LOW")
            c = "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "green"
            console.print(f" - [{c}][{sev}][/{c}] {f.get('description')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _graceful_exit()


import time
import sys
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.json import JSON

# Initialize console with recording enabled
console = Console(record=True, width=100, height=30)

def simulate_typing(text, delay=0.03):
    """Simulate typing effect."""
    for char in text:
        console.print(char, end="")
        time.sleep(delay)
    console.print()

def demo():
    # 1. Clear Screen & Banner
    console.clear()
    banner_text = """
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                 [bold blue]Email Security Analyzer v1.0.0[/bold blue]
    """
    console.print(Panel(Text(banner_text, justify="center", style="bold cyan"), border_style="blue"))
    time.sleep(1)

    # 2. Command
    console.print("[green]user@secure-ops:~$[/green] python main.py -f samples/urgent_invoice.eml")
    time.sleep(1)

    # 3. Initialization
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
        console=console
    ) as progress:
        task1 = progress.add_task("[cyan]Initializing Neural Engines...", total=100)
        task2 = progress.add_task("[magenta]Loading Local Models...", total=100)
        
        while not progress.finished:
            progress.update(task1, advance=2)
            progress.update(task2, advance=3)
            time.sleep(0.05)

    console.print("[+] [bold green]System Ready.[/bold green] Targets loaded: 1\n")
    time.sleep(0.5)

    # 4. Analysis Steps
    steps = [
        ("Parsing email structure...", "OK", "green"),
        ("Extracting headers & metadata...", "OK", "green"),
        ("Checking DKIM signatures...", "FAIL", "red"),
        ("Analyzing SPF records...", "FAIL", "red"),
        ("Extracting URLs...", "FOUND (2)", "yellow"),
        ("Scanning attachments (OCR)...", "CLEAN", "green"),
    ]

    for step, status, color in steps:
        time.sleep(0.4)
        console.print(f"[*] {step:<40} [{color}]{status}[/{color}]")

    time.sleep(0.5)
    console.print("\n[bold yellow][!] Suspicious indicators detected. Engaging Advanced AI Analysis...[/bold yellow]")
    time.sleep(1)

    # 5. Live Analysis Simulation
    console.print("[*] Connecting to [blue]Google Gemini Pro[/blue] for semantic analysis...")
    time.sleep(1.5)
    
    console.print("[*] Scraping URL content: [underline]http://login-verify-account.com[/underline]...")
    time.sleep(1.2)
    
    # 6. Final Report
    console.print("\n" + "="*80)
    console.print("[bold red]🚨 CRITICAL THREAT DETECTED[/bold red]", justify="center")
    console.print("="*80 + "\n")

    report = {
        "risk_level": "CRITICAL",
        "score": 98,
        "findings": [
            {
                "heuristic": "open_redirect",
                "severity": "HIGH",
                "description": "URL redirects to unverified domain"
            },
            {
                "heuristic": "llm_analysis",
                "severity": "CRITICAL",
                "description": "AI detected Urgent Action + Credential Harvesting intent"
            }
        ],
        "summary": "This email attempts to impersonate specific urgency patterns typical of CEO Fraud."
    }
    
    console.print(JSON.from_data(report))
    console.print("\n[bold red][!] ACTION BLOCKED: Email quarantined.[/bold red]")

    # Save SVG - Removed theme argument to fix AttributeError
    console.save_svg("demo.svg", title="Phishing Analyzer Demo")
    print("\nDemo saved to demo.svg")

if __name__ == "__main__":
    demo()

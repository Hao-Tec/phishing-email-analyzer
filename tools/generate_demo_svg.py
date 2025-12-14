import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
import time
import os

# Initialize console with recording enabled
console = Console(record=True, width=100, height=35)

def print_banner():
    banner_text = """
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    """
    console.print(Panel(Text(banner_text, style="bold cyan"), title="v1.0.0", subtitle="Enterprise Phishing Defense"))

def simulate_scan():
    console.print()
    console.print("[bold green]➜[/] Initializing Phishing Email Analyzer...", style="green")
    time.sleep(0.5)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task1 = progress.add_task("[cyan]Loading ML Models...", total=100)
        time.sleep(0.5)
        progress.update(task1, completed=100)
        
        task2 = progress.add_task("[cyan]Verifying Threat Intelligence APIs...", total=100)
        time.sleep(0.5)
        progress.update(task2, completed=100)
        
        task3 = progress.add_task("[cyan]Scanning [bold white]invoice_urgent_v2.eml[/]...", total=100)
        time.sleep(1)
        progress.update(task3, completed=100)

    console.print("[bold green]✔[/] Analysis Complete.")
    console.print()

    # Create Summary Table
    table = Table(title="Analysis Report: invoice_urgent_v2.eml", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Status", justify="center")

    table.add_row("Sender Identity", "support@micr0soft.com", "[bold red]FAILED (DKIM)[/]")
    table.add_row("Link Analysis", "http://login-verify-azure.tk", "[bold red]CRITICAL (PhishTank)[/]")
    table.add_row("ML Confidence", "98.5% Phishing Probability", "[bold red]HIGH[/]")
    table.add_row("AI Analysis", "Urgency + Credential Harvesting", "[bold red]MALICIOUS[/]")
    
    console.print(table)
    console.print()
    
    # Final Verdict Panel
    verdict = Panel(
        """
        [bold red]🚨 CRITICAL THREAT DETECTED[/]
        
        [white]Action Required:[/white] [bold red]BLOCK SENDER & QUARANTINE[/]
        [white]Risk Score:[/white]    [bold red]100/100[/]
        """,
        title="Final Verdict",
        border_style="red"
    )
    console.print(verdict)

if __name__ == "__main__":
    print_banner()
    simulate_scan()
    
    # Save SVG
    output_path = os.path.join("media_kit", "demo_terminal.svg")
    os.makedirs("media_kit", exist_ok=True)
    console.save_svg(output_path, title="Phishing Analyzer CLI")
    print(f"Generated SVG at {output_path}")

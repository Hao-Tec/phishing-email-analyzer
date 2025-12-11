# flake8: noqa
import sys
import time
import random
from rich.console import Console
from rich.style import Style


def print_banner():
    """Print the startup banner with hacker-style boot sequence."""
    console = Console()

    # "Massive" Banner - ANSI Shadow / Block Style
    # PHISHING
    l1 = r"██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ "
    l2 = r"██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ "
    l3 = r"██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗"
    l4 = r"██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║"
    l5 = r"██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝"
    l6 = r"╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ "

    # ANALYZER
    l7 = r" █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ "
    l8 = r"██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗"
    l9 = r"███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝"
    l10 = r"██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗"
    l11 = r"██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║"
    l12 = r"╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝"

    # Print "PHISHING" in Gradient Red->DarkRed
    console.print(f"[bold bright_red]{l1}[/bold bright_red]")
    console.print(f"[bold bright_red]{l2}[/bold bright_red]")
    console.print(f"[bold red]{l3}[/bold red]")
    console.print(f"[bold red]{l4}[/bold red]")
    console.print(f"[bold dark_red]{l5}[/bold dark_red]")
    console.print(f"[bold dark_red]{l6}[/bold dark_red]")

    # Print "ANALYZER" in White/Grey
    console.print(f"[bold white]{l7}[/bold white]")
    console.print(f"[bold white]{l8}[/bold white]")
    console.print(f"[bold white]{l9}[/bold white]")
    console.print(f"[bold white]{l10}[/bold white]")
    console.print(f"[bold #888888]{l11}[/bold #888888]")
    console.print(f"[bold #888888]{l12}[/bold #888888]")

    console.print()

    # Hacker-style Boot Sequence
    checks = [
        "Initializing Neural Engine",
        "Loading Pattern Definitions",
        "Bypassing Security Filters",
        "Connecting to Threat Intel",
        "Optimizing Heuristics",
    ]

    for check in checks:
        time.sleep(0.05)  # Fast boot feel
        console.print(f"[bold green][+][/bold green] {check}...", end="\r")
        time.sleep(0.1)
        console.print(
            f"[bold green][+][/bold green] {check}... [bold cyan]OK[/bold cyan]"
        )

    console.print()

    # Metadata Box
    console.print(
        " [bold yellow]VERSION[/bold yellow]: [red]v1.0.0[/red]   "
        " [bold yellow]BUILD[/bold yellow]: [blue]STABLE[/blue]   "
        " [bold yellow]CODED BY[/bold yellow]: [bold white]The TECHMASTER[/bold white]"
    )
    console.print(
        " [bold yellow]GITHUB[/bold yellow]:  [underline green]https://github.com/Hao-Tec/phishing-email-analyzer[/underline green]"
    )
    console.print(
        " [bold yellow]SYSTEM[/bold yellow]:  [bold green]ONLINE & READY[/bold green]"
    )
    console.print()
    # Separator line
    console.print("[bold red]" + "=" * 65 + "[/bold red]")
    console.print()

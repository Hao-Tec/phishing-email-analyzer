# flake8: noqa
import sys
import time
from rich.console import Console


def print_banner():
    """Print the startup banner with hacker-style boot sequence (Centered)."""
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

    # Print "PHISHING" in Gradient Red->DarkRed (Centered)
    for line in [l1, l2, l3, l4, l5, l6]:
        # Using justify="center" for ASCII art works well
        if "██████╔╝" in line or "██╔═══╝" in line:
            console.print(f"[bold red]{line}[/bold red]", justify="center")
        elif "██║" in line:
            console.print(f"[bold dark_red]{line}[/bold dark_red]", justify="center")
        else:
            console.print(
                f"[bold bright_red]{line}[/bold bright_red]", justify="center"
            )

    # Print "ANALYZER" in White/Grey (Centered)
    for line in [l7, l8, l9, l10, l11, l12]:
        if "███████╗" in line or "██║  ██║" in line:
            console.print(f"[bold #888888]{line}[/bold #888888]", justify="center")
        else:
            console.print(f"[bold white]{line}[/bold white]", justify="center")

    console.print()

    # Hacker-style Boot Sequence (Centered Block)
    checks = [
        "Initializing Neural Engine",
        "Loading Pattern Definitions",
        "Bypassing Security Filters",
        "Connecting to Threat Intel",
        "Optimizing Heuristics",
    ]

    # Calculate padding to center the block
    max_len = max(len(c) for c in checks) + len("[+] ... OK") + 2
    padding = (console.width - max_len) // 2
    pad_str = " " * padding

    for check in checks:
        time.sleep(0.05)
        # We can't use justify="center" effectively with end="\r" and partial updates easily
        # So we manually pad.
        console.print(f"{pad_str}[bold green][+][/bold green] {check}...", end="\r")
        time.sleep(0.1)
        console.print(
            f"{pad_str}[bold green][+][/bold green] {check}... [bold cyan]OK[/bold cyan]"
        )

    console.print()

    # Metadata Box (Centered)
    # Using justify="center" handles the lines automatically
    console.print(
        " [bold yellow]VERSION[/bold yellow]: [red]v1.0.0[/red]    "
        " [bold yellow]BUILD[/bold yellow]: [blue]STABLE[/blue]    "
        " [bold yellow]CODED BY[/bold yellow]: [bold white]The TECHMASTER[/bold white]",
        justify="center",
    )
    console.print(
        " [bold yellow]GITHUB[/bold yellow]:  [underline green]https://github.com/Hao-Tec/phishing-email-analyzer[/underline green]",
        justify="center",
    )
    console.print(
        " [bold yellow]SYSTEM[/bold yellow]:  [bold green]ONLINE & READY[/bold green]",
        justify="center",
    )
    console.print()
    # Separator line
    console.print(f"[bold red]{'='*65}[/bold red]", justify="center")
    console.print()

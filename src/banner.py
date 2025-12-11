# flake8: noqa
from rich.console import Console


def print_banner():
    """Print the startup banner."""
    console = Console()

    # ASCII Art with integrated Version number
    # We use raw strings but have to be careful with backslashes
    # We'll print it line by line to allow specific coloring/version placement

    l1 = r"    ____  _     _     _     _              "
    l2 = r"   |  _ \| |__ (_)___| |__ (_)_ __   __ _ "
    l3 = r"   | |_) | '_ \| / __| '_ \| | '_ \ / _` |"
    l4 = r"   |  __/| | | | \__ \ | | | | | | | (_| |"
    l5 = r"   |_|   |_| |_|_|___/_| |_|_|_| |_|\__, |"
    l6 = r"                                    |___/ "
    l7 = r"       _                _                    "
    l8 = r"      / \   _ __   __ _| |_   _ _______ _ __   [bold red]v1.0.0[/bold red]"
    l9 = r"     / _ \ | '_ \ / _` | | | | |_  / _ \ '__|  [dim]Enterprise Edition[/dim]"
    l10 = r"    / ___ \| | | | (_| | | |_| |/ /  __/ |   "
    l11 = r"   /_/   \_\_| |_|\__,_|_|\__, /___\___|_|   "
    l12 = r"                          |___/              "

    console.print(f"[bold cyan]{l1}[/bold cyan]")
    console.print(f"[bold cyan]{l2}[/bold cyan]")
    console.print(f"[bold cyan]{l3}[/bold cyan]")
    console.print(f"[bold cyan]{l4}[/bold cyan]")
    console.print(f"[bold cyan]{l5}[/bold cyan]")
    console.print(f"[bold cyan]{l6}[/bold cyan]")

    # Gradient shift for the second word
    console.print(f"[bold blue]{l7}[/bold blue]")
    console.print(f"[bold blue]{l8}[/bold blue]")
    console.print(f"[bold blue]{l9}[/bold blue]")
    console.print(f"[bold blue]{l10}[/bold blue]")
    console.print(f"[bold blue]{l11}[/bold blue]")
    console.print(f"[bold blue]{l12}[/bold blue]")

    # Custom colored info lines matching the requested style
    console.print(
        "[bold cyan]Phishing Email Analyzer[/bold cyan] | "
        "[bold white]The advanced phishing detection tool[/bold white]"
    )
    console.print(
        "[bold cyan]Git link[/bold cyan] - "
        "[underline green]https://github.com/Hao-Tec/phishing-email-analyzer.git[/underline green]"
    )
    console.print(
        "[bold cyan]Author[/bold cyan]   - "
        "( [bold yellow]The TECHMASTER[/bold yellow] )"
    )
    console.print()

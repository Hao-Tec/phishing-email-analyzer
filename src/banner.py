from rich.console import Console
from rich.panel import Panel


def print_banner():
    """Print the startup banner."""
    console = Console()

    banner_text = r"""
    ____  _     _     _     _              
   |  _ \| |__ (_)___| |__ (_)_ __   __ _ 
   | |_) | '_ \| / __| '_ \| | '_ \ / _` |
   |  __/| | | | \__ \ | | | | | | | (_| |
   |_|   |_| |_|_|___/_| |_|_|_| |_|\__, |
                                    |___/ 
       _                _                    
      / \   _ __   __ _| |_   _ _______ _ __ 
     / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
    / ___ \| | | | (_| | | |_| |/ /  __/ |   
   /_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
                          |___/              
    """

    console.print(f"[bold cyan]{banner_text}[/bold cyan]")

    # Custom colored info lines matching the requested style
    console.print(
        "[bold cyan]Phishing Email Analyzer[/bold cyan] | "
        "[bold white]The advanced phishing detection tool - Python 3[/bold white]"
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

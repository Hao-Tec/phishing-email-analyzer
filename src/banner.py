
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
    
    info = (
        "[bold white]Version:[/bold white] [green]v1.0.0[/green] | "
        "[bold white]Author:[/bold white] [yellow]Hao-Tec[/yellow]\n"
        "[bold white]Hybrid AI Engine:[/bold white] [bold green]ONLINE[/bold green]"
    )
    
    console.print(Panel(info, border_style="blue", expand=False))
    console.print()

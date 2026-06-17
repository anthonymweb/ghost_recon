from rich.console import Console
from rich.text import Text
from datetime import datetime

console = Console()


def log_info(module: str, message: str):
    console.print(f"  [bold cyan][[*]][/bold cyan] [bold white]{module}[/bold white] [cyan]{message}[/cyan]")


def log_success(module: str, message: str):
    console.print(f"  [bold green][[+]][/bold green] [bold white]{module}[/bold white] [green]{message}[/green]")


def log_warning(module: str, message: str):
    console.print(f"  [bold yellow][[!]][/bold yellow] [bold white]{module}[/bold white] [yellow]{message}[/yellow]")


def log_error(module: str, message: str):
    console.print(f"  [bold red][[-]][/bold red] [bold white]{module}[/bold white] [red]{message}[/red]")


def log_module_header(module: str):
    console.print()
    console.rule(f"[bold purple]{' ' + module + ' '}[/bold purple]", style="purple")
    console.print()


def log_finding(label: str, value: str, severity: str = "info"):
    colors = {"info": "cyan", "low": "green", "medium": "yellow", "high": "orange1", "critical": "red"}
    color = colors.get(severity, "white")
    console.print(f"    [bold {color}]{label}:[/bold {color}] [white]{value}[/white]")

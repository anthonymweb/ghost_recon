from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns


def _make_gradient_text(text: str, colors: list[str]) -> Text:
    result = Text()
    n = len(text)
    for i, ch in enumerate(text):
        color = colors[int(i / n * len(colors))]
        result.append(ch, style=f"bold {color}")
    return result


GRADIENT = ["bright_cyan", "cyan", "bright_blue", "cyan", "bright_cyan"]


def print_banner():
    console = Console()

    console.print()
    console.print(Panel(
        _make_gradient_text("GHOSTRECON", GRADIENT),
        border_style="bright_blue",
        padding=(1, 2),
        subtitle="[bright_cyan]v1.0[/bright_cyan]",
    ))
    console.print(
        "  [dim]by GhostChain[/dim]  [dim]·[/dim]  [bold white]Passive OSINT Recon Engine[/bold white]  [dim]·[/dim]  [cyan]Ethical use only[/cyan]"
    )
    console.print()

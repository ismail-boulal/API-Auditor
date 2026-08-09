from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
import json

# THIS IS IA GENERATED FOR BETTER DISPLAY OUTPUT PURPOSES

console = Console()


# ======================================================================
#  GENERIC HELPERS
# ======================================================================

def _fmt_json(data):
    """Return a rich Syntax block for any JSON-serialisable value / raw string."""
    try:
        if isinstance(data, (dict, list)):
            pretty = json.dumps(data, indent=2, ensure_ascii=False)
        else:
            pretty = json.dumps(json.loads(data), indent=2, ensure_ascii=False)
        return Syntax(pretty, "json", theme="monokai", word_wrap=True)
    except (ValueError, TypeError):
        return str(data)


def _method_tag(method):
    colors = {
        "GET": "green",
        "POST": "blue",
        "PUT": "yellow",
        "PATCH": "magenta",
        "DELETE": "red",
    }
    color = colors.get(method, "white")
    return f"[{color}]{method}[/{color}]"


# ======================================================================
#  ENDPOINT DISCOVERY (unchanged)
# ======================================================================

def display_endpoints(endpoints):
    table = Table(title="Discovered Endpoints", show_lines=False)

    table.add_column("Method", justify="left", style="bold")
    table.add_column("Path", style="cyan")
    table.add_column("Auth", justify="left")
    table.add_column("Objects", style="yellow")

    for ep in endpoints:

        if ep.method == "GET":
            method = "[green]GET[/green]"
        elif ep.method == "POST":
            method = "[blue]POST[/blue]"
        elif ep.method == "PUT":
            method = "[yellow]PUT[/yellow]"
        elif ep.method == "PATCH":
            method = "[magenta]PATCH[/magenta]"
        elif ep.method == "DELETE":
            method = "[red]DELETE[/red]"
        else:
            method = ep.method

        auth = (
            "[red]Protected[/red]"
            if ep.authentication.required
            else "[green]Public[/green]"
        )

        objects = (
            ", ".join(ep.object_candidates)
            if ep.object_candidates
            else "-"
        )

        table.add_row(
            method,
            ep.path,
            auth,
            objects,
        )

    console.print(table)


# ======================================================================
#  BOLA DISPLAY (unchanged)
# ======================================================================

def display_bola_header():
    console.rule("[bold cyan]BOLA ENGINE[/bold cyan]")


def display_candidate(score, method, path):
    console.print(f"  [yellow]SCORE={score}[/yellow]  [bold]{method}[/bold] [cyan]{path}[/cyan]")


def display_id_found(id_value, source_url):
    console.print(f"    [green][+][/green] ID found: [bold green]{id_value}[/bold green]")
    console.print(f"    [dim]from {source_url}[/dim]")


def display_result(vulnerable, path, label_a, label_b):
    if vulnerable:
        console.print(Panel(
            f"[bold red]{label_a}[/bold red] accessed [bold red]{label_b}[/bold red]'s object",
            title="[bold red][+] BOLA VULNERABLE[/bold red]",
            border_style="red",
        ))
    else:
        console.print(Panel(
            f"{path}",
            title="[bold green][-] CLEAN[/bold green]",
            border_style="green",
        ))


def display_bodies(body_a, body_b, label_a="User A", label_b="User B"):
    def fmt(b):
        try:
            pretty = json.dumps(json.loads(b), indent=2)
            return Syntax(pretty, "json", theme="monokai", word_wrap=True)
        except (ValueError, TypeError):
            return b

    panel_a = Panel(fmt(body_a), title=f"[cyan]{label_a}[/cyan]", border_style="cyan")
    panel_b = Panel(fmt(body_b), title=f"[magenta]{label_b}[/magenta]", border_style="magenta")
    console.print(Columns([panel_a, panel_b], equal=True, expand=True))


# ======================================================================
#  BFLA DISPLAY
# ======================================================================

def display_bfla_header():
    console.print()
    console.rule("[bold red]BFLA ENGINE[/bold red]  [dim]Broken Function Level Authorization[/dim]")
    console.print()


def display_bfla_ranking(bfla_candidates):
    """bfla_candidates: list of (score, endpoint) tuples, already sorted."""
    table = Table(
        title="[bold]Candidate Endpoints (by suspicion score)[/bold]",
        show_lines=False,
        header_style="bold white on grey23",
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Score", justify="right", style="bold yellow")
    table.add_column("Method", justify="left")
    table.add_column("Path", style="cyan")

    for rank, (score, endpoint) in enumerate(bfla_candidates, start=1):
        table.add_row(
            str(rank),
            str(score),
            _method_tag(endpoint.method),
            endpoint.path,
        )
    console.print(table)
    console.print()


def display_bfla_target(method, path):
    """Announce the endpoint currently being tested."""
    console.print()
    console.print(Rule(style="grey37"))
    console.print(
        f"[bold white]>>> Testing[/bold white]  {_method_tag(method)} [cyan]{path}[/cyan]"
    )


def display_bfla_step(label, value=""):
    """Generic step line, e.g. probe / baseline / attack details."""
    console.print(f"  [blue][*][/blue] [bold]{label}[/bold] [dim]{value}[/dim]")


def display_bfla_check_endpoint(get_url):
    if get_url:
        console.print(f"  [blue][*][/blue] Confirmation endpoint: [cyan]{get_url}[/cyan]")
    else:
        console.print("  [yellow][!][/yellow] No confirmation endpoint available (blind test)")


def display_bfla_attack(method, request_url, body):
    console.print(
        f"  [red][>][/red] Replaying as standard account: {_method_tag(method)} [cyan]{request_url}[/cyan]"
    )
    if body:
        console.print("  [dim]    payload:[/dim]")
        console.print(Panel(_fmt_json(body), border_style="grey37", expand=False))


def display_bfla_diff(before, response_text, after, resource_is_affected):
    """Show before / response / after triplet used for confirmation."""
    before_panel = Panel(_fmt_json(before), title="[cyan]BEFORE[/cyan]", border_style="cyan")
    resp_panel = Panel(_fmt_json(response_text), title="[yellow]ATTACK RESPONSE[/yellow]", border_style="yellow")
    after_panel = Panel(_fmt_json(after), title="[magenta]AFTER[/magenta]", border_style="magenta")
    console.print(Columns([before_panel, after_panel], equal=True, expand=True))
    console.print(resp_panel)

    if resource_is_affected is True:
        console.print("  [bold red][+] Resource state changed after the call[/bold red]")
    elif resource_is_affected == "Unknown":
        console.print("  [yellow][~] Resource state change could not be verified[/yellow]")
    else:
        console.print("  [green][-] No resource state change detected[/green]")


def _confidence_style(confidence):
    styles = {
        "CONFIRMED": ("bold white on red", "[+]"),
        "HIGH":      ("bold red", "[+]"),
        "MEDIUM":    ("bold yellow", "[!]"),
        "AMBIGUOUS": ("yellow", "[~]"),
    }
    return styles.get(str(confidence).upper(), ("white", "[?]"))


def display_bfla_finding(finding):
    """Render a confirmed BFLA finding as a pentest-style report block."""
    style, marker = _confidence_style(finding.confidence)
    endpoint = finding.endpoint

    header = Text()
    header.append(f"{marker} BFLA ", style=style)
    header.append(f"{endpoint.method} {endpoint.path}", style="bold cyan")

    body = Text()
    body.append("Vulnerability : ", style="bold")
    body.append(f"{finding.vulnerability}\n")
    body.append("Endpoint      : ", style="bold")
    body.append(f"{endpoint.method} {endpoint.path}\n")
    body.append("Confidence    : ", style="bold")
    body.append(f"{finding.confidence}\n", style=style)
    body.append("Impact        : ", style="bold")
    body.append("Privileged function reached with a standard-role account")

    console.print(
        Panel(
            body,
            title=header,
            border_style="red" if str(finding.confidence).upper() in ("CONFIRMED", "HIGH") else "yellow",
            expand=False,
        )
    )


def display_bfla_summary(findings):
    console.print()
    console.rule("[bold red]BFLA SUMMARY[/bold red]")
    if not findings:
        console.print(Panel(
            "No BFLA vulnerabilities confirmed.",
            title="[bold green][-] CLEAN[/bold green]",
            border_style="green",
            expand=False,
        ))
        return

    table = Table(show_lines=False, header_style="bold white on grey23")
    table.add_column("Method", justify="left")
    table.add_column("Path", style="cyan")
    table.add_column("Confidence", justify="left")

    for f in findings:
        style, _ = _confidence_style(f.confidence)
        table.add_row(
            _method_tag(f.endpoint.method),
            f.endpoint.path,
            f"[{style}]{f.confidence}[/{style}]",
        )
    console.print(table)
    console.print(
        f"\n  [bold red]{len(findings)}[/bold red] potential BFLA "
        f"{'vulnerability' if len(findings) == 1 else 'vulnerabilities'} reported.\n"
    )
"""
display.py — Rich-powered terminal output for NetScope.

All formatting is centralised here so that capture.py, security.py,
and cli.py never import Rich directly. Swapping the display backend
(e.g. to JSON output for piping) only requires a new Display subclass.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from netscope.parser import ParsedPacket


class Display:
    """Handles all terminal rendering for NetScope."""

    # Protocol → colour mapping for capture output
    PROTO_COLORS = {
        "TCP": "cyan",
        "UDP": "blue",
        "ICMP": "magenta",
    }

    # Risk level → colour
    RISK_COLORS = {
        "high": "red",
        "medium": "yellow",
        "low": "bright_yellow",
        "info": "green",
    }

    def __init__(self):
        self.console = Console()

    # ------------------------------------------------------------------
    # Shared
    # ------------------------------------------------------------------

    def banner(self) -> None:
        self.console.print(
            Panel(
                "[bold cyan]NetScope[/bold cyan]  ·  "
                "Network Packet Analyzer & Security Scanner\n"
                "[dim]github.com/Darth-hub/netscope[/dim]",
                border_style="cyan",
                padding=(0, 2),
            )
        )

    def info(self, msg: str) -> None:
        self.console.print(f"[blue]ℹ[/blue]  {msg}")

    def error(self, msg: str) -> None:
        self.console.print(f"[bold red]✗  Error:[/bold red] {msg}")

    # ------------------------------------------------------------------
    # Capture mode
    # ------------------------------------------------------------------

    def capture_start(self, interface: str, bpf: str, filter_desc: str) -> None:
        self.console.print(
            f"\n[bold]Interface:[/bold] [cyan]{interface}[/cyan]   "
            f"[bold]BPF:[/bold] [dim]{bpf}[/dim]   "
            f"[bold]Filters:[/bold] [dim]{filter_desc}[/dim]"
        )
        self.console.print("[dim]Ctrl-C to stop.[/dim]\n")
        # Column header
        self.console.print(
            f"{'TIME':<12} {'PROTO':<6} {'SRC':<24} {'DST':<24} "
            f"{'FLAGS':<16} {'BYTES':>6}  {'SERVICE'}",
            style="bold dim",
        )
        self.console.rule(style="dim")

    def print_packet(self, pkt: ParsedPacket, verbose: bool = False) -> None:
        color = self.PROTO_COLORS.get(pkt.protocol, "white")
        ts = pkt.timestamp.strftime("%H:%M:%S.%f")[:12]
        src = f"{pkt.src_ip}:{pkt.src_port or '*'}"
        dst = f"{pkt.dst_ip}:{pkt.dst_port or '*'}"
        flags = pkt.flags or pkt.extra.get("type_name", "")
        svc = pkt.service_info or ""
        size = f"{pkt.length}B"

        line = (
            f"{ts:<12} "
            f"[{color}]{pkt.protocol:<6}[/{color}] "
            f"{src:<24} {dst:<24} "
            f"[dim]{(flags or ''):<16}[/dim] "
            f"{size:>6}  "
            f"[green]{svc}[/green]"
        )

        if pkt.is_suspicious:
            line += "  [bold red][!][/bold red]"
        if pkt.is_encrypted:
            line += " [yellow]🔒[/yellow]"

        self.console.print(line)

        if verbose and pkt.extra:
            self.console.print(f"  [dim]{pkt.extra}[/dim]")

    def capture_end(self, count: int) -> None:
        self.console.rule(style="dim")
        self.console.print(
            f"\n[bold]Capture complete.[/bold]  "
            f"Packets captured: [cyan]{count}[/cyan]\n"
        )

    # ------------------------------------------------------------------
    # Scan mode
    # ------------------------------------------------------------------

    def scan_start(self, target: str, ip: str, port_count: int) -> None:
        self.console.print(
            f"\n[bold]Target:[/bold] [cyan]{target}[/cyan] ([dim]{ip}[/dim])  "
            f"[bold]Ports:[/bold] {port_count}\n"
        )

    def port_found(self, port: int, service: str) -> None:
        self.console.print(
            f"  [green]OPEN[/green]  [cyan]{port:<6}[/cyan] [dim]{service}[/dim]"
        )

    def scan_result(self, result) -> None:
        """Render the full scan results table and risk summary."""
        self.console.print()
        self.console.rule("[bold]Scan Results[/bold]")

        if not result.open_ports:
            self.console.print("[yellow]No open ports found.[/yellow]")
            return

        # -- Open ports table --
        table = Table(
            title=f"Open Ports — {result.target} ({result.resolved_ip})",
            box=box.SIMPLE_HEAVY,
            show_lines=False,
        )
        table.add_column("Port", style="cyan", justify="right", min_width=5)
        table.add_column("Service")
        table.add_column("Enc.", justify="center", min_width=4)
        table.add_column("Risk", justify="center", min_width=8)
        table.add_column("Banner", style="dim", max_width=38)
        table.add_column("TLS", style="dim", max_width=38)

        for pr in result.open_ports:
            rc = self.RISK_COLORS.get(pr.risk, "white")
            enc_icon = "[green]✓[/green]" if pr.is_encrypted else "[red]✗[/red]"

            tls_str = ""
            if pr.tls_info:
                if "error" in pr.tls_info:
                    tls_str = f"[red]{pr.tls_info['error'][:38]}[/red]"
                else:
                    d = pr.tls_info
                    days = d.get("days_left")
                    days_str = f" ({days}d)" if days is not None else ""
                    tls_str = f"{d['version']} · exp {d['expiry']}{days_str}"

            table.add_row(
                str(pr.port),
                pr.service,
                enc_icon,
                f"[{rc}]{pr.risk.upper()}[/{rc}]",
                pr.banner[:38] if pr.banner else "",
                tls_str,
            )

        self.console.print(table)

        # -- Risk summary --
        if result.unencrypted_services:
            self.console.print(
                "\n[bold red]⚠  Unencrypted / High-Risk Services:[/bold red]"
            )
            for pr in result.unencrypted_services:
                rc = self.RISK_COLORS[pr.risk]
                self.console.print(
                    f"  [{rc}]•[/{rc}] Port [cyan]{pr.port}[/cyan] "
                    f"({pr.service}) [{rc}]{pr.risk.upper()}[/{rc}] — "
                    "credentials or data may be transmitted in plaintext"
                )

        if result.tls_issues:
            self.console.print("\n[bold yellow]⚠  TLS / Certificate Issues:[/bold yellow]")
            for issue in result.tls_issues:
                self.console.print(f"  [yellow]•[/yellow] {issue}")

        if not result.unencrypted_services and not result.tls_issues:
            self.console.print("\n[green]✓  No critical security issues detected.[/green]")

        self.console.print(
            f"\n[dim]Completed in {result.scan_time:.2f}s — "
            f"{len(result.open_ports)} open port(s) found.[/dim]\n"
        )

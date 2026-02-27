"""Rich console output: tables, panels, progress bars."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from airsnitch.core.types import APInfo, ClientInfo, Finding, RiskLevel, RiskScore, Severity

console = Console()

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.INFO: "dim",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
    Severity.EMERGENCY: "bold white on red",
}

RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold white on red",
}


def print_banner() -> None:
    banner = Text()
    banner.append("AirSnitch Scanner", style="bold cyan")
    banner.append(" v0.1.0\n", style="dim")
    banner.append("Hotel Wi-Fi Client Isolation Bypass Assessment", style="italic")
    console.print(Panel(banner, border_style="cyan"))


def print_network_info(gateway_ip: str | None, gateway_mac: str | None, ssid: str | None, client_count: int) -> None:
    table = Table(title="Network Context", show_header=False, border_style="blue")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("SSID", ssid or "unknown")
    table.add_row("Gateway IP", gateway_ip or "unknown")
    table.add_row("Gateway MAC", gateway_mac or "unknown")
    table.add_row("Clients Found", str(client_count))
    console.print(table)
    console.print()


def print_ap_info(ap: APInfo) -> None:
    table = Table(title="Access Point", show_header=False, border_style="blue")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("BSSID", ap.bssid)
    table.add_row("SSID", ap.ssid)
    table.add_row("Vendor", ap.vendor or "unknown")
    table.add_row("Model", ap.model or "unknown")
    table.add_row("Firmware", ap.firmware or "unknown")
    table.add_row("Band", ap.band.value)
    console.print(table)
    console.print()


def print_clients(clients: list[ClientInfo]) -> None:
    table = Table(title="Discovered Clients", border_style="green")
    table.add_column("#", style="dim")
    table.add_column("MAC")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("Vendor", style="dim")
    for i, c in enumerate(clients, 1):
        table.add_row(str(i), c.mac, c.ip or "-", c.hostname or "-", c.vendor or "-")
    console.print(table)
    console.print()


def print_finding(finding: Finding) -> None:
    color = SEVERITY_COLORS.get(finding.severity, "white")
    severity_text = f"[{color}]{finding.severity.name}[/{color}]"

    panel_content = Text()
    panel_content.append(f"Score: {finding.score:.1f}  Confidence: {finding.confidence:.0%}\n\n")
    panel_content.append(f"{finding.description}\n\n")
    panel_content.append("Evidence: ", style="bold")
    panel_content.append(f"{finding.evidence}\n\n")
    panel_content.append("Remediation: ", style="bold")
    panel_content.append(finding.remediation)

    console.print(
        Panel(
            panel_content,
            title=f"{finding.test_name} - {severity_text}",
            border_style=color.split()[-1],  # Get base color without bold
        )
    )


def print_risk_score(score: RiskScore) -> None:
    color = RISK_COLORS.get(score.level, "white")
    console.print()
    console.print(
        Panel(
            Text(f"Overall Risk: {score.overall:.1f}/10 - {score.level.value}", style=color),
            title="Risk Assessment",
            border_style=color.split()[-1],
        )
    )
    console.print()


def print_findings_table(findings: list[Finding]) -> None:
    table = Table(title="Findings Summary", border_style="red")
    table.add_column("Test", style="bold")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Score", justify="right")
    table.add_column("Result")

    for f in sorted(findings, key=lambda x: x.score, reverse=True):
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f.test_name,
            f"[{color}]{f.severity.name}[/{color}]",
            f"{f.confidence:.0%}",
            f"{f.score:.1f}",
            f.description[:60] + "..." if len(f.description) > 60 else f.description,
        )

    console.print(table)


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )

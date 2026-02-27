"""CLI entry point with Click command groups."""

from __future__ import annotations

from pathlib import Path

import click

from airsnitch import __version__
from airsnitch.attacks.downlink_spoof import DownlinkSpoofTest
from airsnitch.attacks.gateway_bounce import GatewayBounceTest
from airsnitch.attacks.gtk_injection import GTKInjectionTest
from airsnitch.attacks.uplink_impersonation import UplinkImpersonationTest
from airsnitch.core.adapter import WifiAdapter, AdapterError
from airsnitch.core.context import build_context
from airsnitch.core.packets import PacketEngine
from airsnitch.core.types import APInfo, ClientInfo, Finding, NetworkContext
from airsnitch.discovery.fingerprint import RouterFingerprinter
from airsnitch.discovery.scanner import NetworkScanner
from airsnitch.reporting import json_report, terminal
from airsnitch.reporting.terminal import console
from airsnitch.safeguards.audit import AuditLogger
from airsnitch.safeguards.authorization import (
    confirm_injection,
    generate_auth_code,
    require_root,
    show_disclaimer_and_confirm,
)
from airsnitch.safeguards.rate_limiter import RateLimiter
from airsnitch.scoring.engine import score_findings


class ScanContext:
    """Shared state across CLI commands. Lazy initialization of heavy resources."""

    def __init__(
        self,
        interface: str,
        ssid: str | None,
        password: str | None,
        auth_code: str | None,
        output: str | None,
        pps: int,
        verbosity: int,
        batch: bool,
    ):
        self.interface = interface
        self.ssid = ssid
        self.password = password
        self.auth_code = auth_code
        self.output = Path(output) if output else None
        self.pps = pps
        self.verbosity = verbosity
        self.batch = batch
        # Lazy-initialized resources
        self._audit: AuditLogger | None = None
        self._rate_limiter: RateLimiter | None = None
        self._net_ctx = None
        self._engine: PacketEngine | None = None
        self._adapter: WifiAdapter | None = None

    @property
    def audit(self) -> AuditLogger:
        if self._audit is None:
            self._audit = AuditLogger()
        return self._audit

    @property
    def rate_limiter(self) -> RateLimiter:
        if self._rate_limiter is None:
            self._rate_limiter = RateLimiter(self.pps)
        return self._rate_limiter

    @property
    def net_ctx(self) -> NetworkContext:
        if self._net_ctx is None:
            self._net_ctx = build_context(self.interface, self.ssid, self.password)
        return self._net_ctx

    @property
    def adapter(self) -> WifiAdapter | None:
        """Try to create adapter; return None if interface validation fails."""
        if self._adapter is None:
            try:
                self._adapter = WifiAdapter(self.interface)
            except AdapterError:
                pass  # Will work without adapter (no monitor mode)
        return self._adapter

    @property
    def engine(self) -> PacketEngine:
        if self._engine is None:
            self._engine = PacketEngine(
                self.interface, self.rate_limiter, self.audit, adapter=self.adapter
            )
            # Store our MAC in context
            try:
                self.net_ctx.our_mac = self._engine.mac
            except Exception:
                pass
        return self._engine

    def close(self) -> None:
        """Tear down all resources. Called on CLI exit via ctx.call_on_close."""
        if self._adapter:
            try:
                self._adapter.cleanup()
            except Exception:
                pass
        if self._audit:
            try:
                self._audit.log_session_end()
            except Exception:
                pass


@click.group()
@click.option("--interface", "-i", required=True, help="Wi-Fi interface to use")
@click.option("--ssid", "-s", help="Target network SSID")
@click.option(
    "--password", "-p",
    envvar="AIRSNITCH_PASSWORD",
    help="Wi-Fi password (or set AIRSNITCH_PASSWORD env var)",
)
@click.option("--auth-code", "-a", help="Authorization code (AIRSNITCH-XXXXXXXX)")
@click.option("--output", "-o", help="Output file path for JSON report")
@click.option("--pps", default=10, show_default=True, help="Max packets per second")
@click.option("--verbosity", "-v", count=True, help="Increase verbosity (-v, -vv, -vvv)")
@click.option("--yes", "-y", is_flag=True, help="Skip per-target injection confirmations (batch mode)")
@click.version_option(version=__version__, prog_name="airsnitch")
@click.pass_context
def cli(
    ctx: click.Context,
    interface: str,
    ssid: str | None,
    password: str | None,
    auth_code: str | None,
    output: str | None,
    pps: int,
    verbosity: int,
    yes: bool,
) -> None:
    """AirSnitch - Hotel Wi-Fi client isolation bypass security assessment."""
    ctx.ensure_object(dict)
    scan = ScanContext(interface, ssid, password, auth_code, output, pps, verbosity, yes)
    ctx.obj = scan
    ctx.call_on_close(scan.close)


@cli.command()
@click.pass_context
def discover(ctx: click.Context) -> None:
    """Scan network for clients and identify gateway."""
    scan: ScanContext = ctx.obj
    require_root()
    terminal.print_banner()

    scanner = NetworkScanner(scan.net_ctx, scan.engine, scan.audit)

    with terminal.create_progress() as progress:
        task = progress.add_task("Detecting gateway...", total=3)

        gw = scanner.detect_gateway()
        if gw:
            scan.net_ctx.gateway_ip, scan.net_ctx.gateway_mac = gw
        progress.update(task, advance=1, description="ARP sweep...")

        clients = scanner.arp_sweep()
        scan.net_ctx.clients = clients
        progress.update(task, advance=1, description="Passive sniff...")

        passive = scanner.passive_sniff(duration=10)
        known_macs = {c.mac for c in clients}
        for c in passive:
            if c.mac not in known_macs:
                clients.append(c)
                known_macs.add(c.mac)
        scan.net_ctx.clients = clients
        progress.update(task, advance=1)

    terminal.print_network_info(
        scan.net_ctx.gateway_ip,
        scan.net_ctx.gateway_mac,
        scan.net_ctx.ssid,
        len(clients),
    )
    terminal.print_clients(clients)
    scan.audit.log_session_end()


@cli.command()
@click.pass_context
def fingerprint(ctx: click.Context) -> None:
    """Identify router vendor, model, and known vulnerabilities."""
    scan: ScanContext = ctx.obj
    require_root()
    terminal.print_banner()

    scanner = NetworkScanner(scan.net_ctx, scan.engine, scan.audit)
    gw = scanner.detect_gateway()
    if gw:
        scan.net_ctx.gateway_ip, scan.net_ctx.gateway_mac = gw

    fp = RouterFingerprinter(scan.net_ctx, scan.audit)
    ap = fp.fingerprint()
    if ap:
        terminal.print_ap_info(ap)
        vulns = fp.get_known_vulnerabilities(ap)
        if vulns:
            console.print(f"[red]Known vulnerable to: {', '.join(vulns)}[/red]")
        else:
            console.print("[green]No known vulnerabilities in database[/green]")
    else:
        console.print("[yellow]Could not fingerprint access point[/yellow]")

    scan.audit.log_session_end()


def _should_confirm(scan: ScanContext, test_name: str, target_mac: str) -> bool:
    """Check whether to proceed with injection. Skips prompt in batch mode."""
    if scan.batch:
        return True
    return confirm_injection(test_name, target_mac)


def _run_attack_test(
    scan: ScanContext,
    test_cls: type,
    target_mac: str | None,
) -> list[Finding]:
    """Common runner for attack test commands."""
    require_root()
    if not show_disclaimer_and_confirm(scan.auth_code):
        raise SystemExit(1)

    terminal.print_banner()

    scanner = NetworkScanner(scan.net_ctx, scan.engine, scan.audit)
    gw = scanner.detect_gateway()
    if gw:
        scan.net_ctx.gateway_ip, scan.net_ctx.gateway_mac = gw

    if target_mac:
        targets = [ClientInfo(mac=target_mac)]
    else:
        targets = scanner.arp_sweep()
        scan.net_ctx.clients = targets

    if not targets:
        console.print("[yellow]No targets found[/yellow]")
        return []

    test = test_cls(scan.net_ctx, scan.engine, scan.audit)
    can_run, reason = test.preflight_check()
    if not can_run:
        console.print(f"[red]Preflight failed: {reason}[/red]")
        return []

    findings: list[Finding] = []
    for target in targets:
        if not _should_confirm(scan, test.name, target.mac):
            continue
        try:
            finding = test.execute(target)
            findings.append(finding)
            terminal.print_finding(finding)
        finally:
            test.cleanup()

    return findings


@cli.command("test-gtk")
@click.option("--target", "-t", help="Target client MAC address")
@click.pass_context
def test_gtk(ctx: click.Context, target: str | None) -> None:
    """Test GTK broadcast injection bypass."""
    scan: ScanContext = ctx.obj
    findings = _run_attack_test(scan, GTKInjectionTest, target)
    _output_results(scan, findings)


@cli.command("test-gateway")
@click.option("--target", "-t", help="Target client MAC address")
@click.pass_context
def test_gateway(ctx: click.Context, target: str | None) -> None:
    """Test L2/L3 gateway bounce bypass."""
    scan: ScanContext = ctx.obj
    findings = _run_attack_test(scan, GatewayBounceTest, target)
    _output_results(scan, findings)


@cli.command("test-downlink")
@click.option("--target", "-t", help="Target client MAC address")
@click.pass_context
def test_downlink(ctx: click.Context, target: str | None) -> None:
    """Test cross-band downlink MAC spoof."""
    scan: ScanContext = ctx.obj
    findings = _run_attack_test(scan, DownlinkSpoofTest, target)
    _output_results(scan, findings)


@cli.command("test-uplink")
@click.option("--target", "-t", help="Target client MAC address")
@click.pass_context
def test_uplink(ctx: click.Context, target: str | None) -> None:
    """Test backend device uplink impersonation."""
    scan: ScanContext = ctx.obj
    findings = _run_attack_test(scan, UplinkImpersonationTest, target)
    _output_results(scan, findings)


@cli.command("full-scan")
@click.option("--target", "-t", help="Target client MAC (default: all discovered)")
@click.pass_context
def full_scan(ctx: click.Context, target: str | None) -> None:
    """Run all tests and generate comprehensive report."""
    scan: ScanContext = ctx.obj
    require_root()

    if not show_disclaimer_and_confirm(scan.auth_code):
        raise SystemExit(1)

    terminal.print_banner()

    # Discovery phase
    scanner = NetworkScanner(scan.net_ctx, scan.engine, scan.audit)
    with terminal.create_progress() as progress:
        task = progress.add_task("Discovery...", total=4)

        gw = scanner.detect_gateway()
        if gw:
            scan.net_ctx.gateway_ip, scan.net_ctx.gateway_mac = gw
        progress.update(task, advance=1, description="Scanning clients...")

        clients = scanner.arp_sweep()
        scan.net_ctx.clients = clients
        progress.update(task, advance=1, description="Fingerprinting AP...")

        fp = RouterFingerprinter(scan.net_ctx, scan.audit)
        ap = fp.fingerprint()
        progress.update(task, advance=1, description="Passive enumeration...")

        passive = scanner.passive_sniff(duration=10)
        known_macs = {c.mac for c in clients}
        for c in passive:
            if c.mac not in known_macs:
                clients.append(c)
                known_macs.add(c.mac)
        scan.net_ctx.clients = clients
        progress.update(task, advance=1)

    terminal.print_network_info(
        scan.net_ctx.gateway_ip, scan.net_ctx.gateway_mac, scan.net_ctx.ssid, len(clients)
    )
    if ap:
        terminal.print_ap_info(ap)
    terminal.print_clients(clients)

    if target:
        targets = [ClientInfo(mac=target)]
    else:
        targets = clients

    if not targets:
        console.print("[yellow]No targets found. Exiting.[/yellow]")
        return

    # Run all tests
    all_findings: list[Finding] = []
    test_classes = [GTKInjectionTest, GatewayBounceTest, DownlinkSpoofTest, UplinkImpersonationTest]

    for test_cls in test_classes:
        test = test_cls(scan.net_ctx, scan.engine, scan.audit)
        can_run, reason = test.preflight_check()
        if not can_run:
            console.print(f"[dim]Skipping {test.name}: {reason}[/dim]")
            continue

        for t in targets:
            if not _should_confirm(scan, test.name, t.mac):
                continue
            try:
                finding = test.execute(t)
                all_findings.append(finding)
            finally:
                test.cleanup()

    # Score and report
    risk = score_findings(all_findings, ap)
    terminal.print_findings_table(all_findings)
    terminal.print_risk_score(risk)

    _output_results(scan, all_findings, ap)
    scan.audit.log_session_end()


@cli.command("gen-auth-code")
@click.option("--hotel-name", required=True, help="Hotel name for auth code generation")
def gen_auth_code(hotel_name: str) -> None:
    """Generate an authorization code for testing."""
    code = generate_auth_code(hotel_name)
    console.print(f"Authorization code: [bold green]{code}[/bold green]")


@cli.command()
@click.option("--target", "-t", help="Target client MAC to monitor")
@click.option("--duration", "-d", default=60, help="Monitor duration in seconds")
@click.pass_context
def monitor(ctx: click.Context, target: str | None, duration: int) -> None:
    """Continuous monitoring mode - passive observation."""
    scan: ScanContext = ctx.obj
    require_root()
    terminal.print_banner()

    console.print(f"[cyan]Monitoring on {scan.interface} for {duration}s...[/cyan]")

    scanner = NetworkScanner(scan.net_ctx, scan.engine, scan.audit)
    clients = scanner.passive_sniff(duration=duration)
    scan.net_ctx.clients = clients

    terminal.print_clients(clients)
    scan.audit.log_session_end()


def _output_results(
    scan: ScanContext,
    findings: list[Finding],
    ap: APInfo | None = None,
) -> None:
    """Output findings as JSON if output path specified."""
    if scan.output and findings:
        risk = score_findings(findings)
        json_report.generate_report(scan.net_ctx, risk, ap=ap, output_path=scan.output)
        console.print(f"\n[green]Report saved to {scan.output}[/green]")


if __name__ == "__main__":
    cli()

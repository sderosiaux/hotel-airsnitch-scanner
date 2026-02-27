"""Legal disclaimers, authorization verification, and confirmation prompts."""

from __future__ import annotations

import hashlib
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from airsnitch.config import AUTH_CODE_PREFIX

console = Console()

LEGAL_DISCLAIMER = """\
This tool performs ACTIVE security testing on Wi-Fi networks.
Unauthorized use against networks you do not own or have explicit
written authorization to test is ILLEGAL in most jurisdictions.

By proceeding, you confirm:
  1. You have explicit written authorization from the network owner
  2. You understand this tool sends packets that may disrupt service
  3. You accept full legal responsibility for its use
  4. You are operating within applicable laws and regulations

Violations may result in criminal prosecution under:
  - Computer Fraud and Abuse Act (US)
  - Computer Misuse Act (UK)
  - Equivalent legislation in your jurisdiction
"""

JURISDICTION_WARNING = """\
WARNING: Laws governing wireless security testing vary by country.
Some jurisdictions criminalize ANY unauthorized network probing.
Ensure you have documented authorization BEFORE proceeding.
"""


def validate_auth_code(code: str) -> bool:
    """Validate authorization code format: AIRSNITCH-<8 hex chars>."""
    if not code.startswith(AUTH_CODE_PREFIX):
        return False
    suffix = code[len(AUTH_CODE_PREFIX) :]
    if len(suffix) != 8:
        return False
    try:
        int(suffix, 16)
    except ValueError:
        return False
    return True


def generate_auth_code(hotel_name: str) -> str:
    """Generate a deterministic auth code from hotel name (for testing)."""
    digest = hashlib.sha256(hotel_name.encode()).hexdigest()[:8].upper()
    return f"{AUTH_CODE_PREFIX}{digest}"


def show_disclaimer_and_confirm(auth_code: str | None) -> bool:
    """Display legal disclaimer and verify authorization.

    Returns True if authorized to proceed, False otherwise.
    """
    console.print()
    console.print(
        Panel(
            Text(LEGAL_DISCLAIMER, style="bold red"),
            title="LEGAL DISCLAIMER",
            border_style="red",
        )
    )
    console.print()
    console.print(
        Panel(
            Text(JURISDICTION_WARNING, style="yellow"),
            title="JURISDICTION",
            border_style="yellow",
        )
    )
    console.print()

    if auth_code is None:
        console.print(
            "[red]No authorization code provided.[/red]\n"
            "Use --auth-code AIRSNITCH-XXXXXXXX to provide authorization.\n"
            "Generate a code with: airsnitch gen-auth-code --hotel-name 'Hotel Name'"
        )
        return False

    if not validate_auth_code(auth_code):
        console.print(f"[red]Invalid authorization code: {auth_code}[/red]")
        return False

    console.print(f"[green]Authorization code accepted: {auth_code}[/green]\n")

    if not click.confirm("Do you confirm you have written authorization to test this network?"):
        console.print("[yellow]Aborted by user.[/yellow]")
        return False

    return True


def confirm_injection(test_name: str, target: str) -> bool:
    """Require explicit confirmation before any packet injection test."""
    console.print(
        f"\n[yellow]About to execute: [bold]{test_name}[/bold] targeting {target}[/yellow]"
    )
    return click.confirm("Proceed with injection test?")


def require_root() -> None:
    """Exit if not running as root."""
    import os

    if os.geteuid() != 0:
        console.print("[red]This tool requires root privileges. Run with sudo.[/red]")
        sys.exit(1)

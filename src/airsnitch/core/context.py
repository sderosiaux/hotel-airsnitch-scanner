"""Network context builder - populates NetworkContext from interface."""

from __future__ import annotations

from airsnitch.core.types import NetworkContext


def build_context(
    interface: str,
    ssid: str | None = None,
    password: str | None = None,
) -> NetworkContext:
    """Build initial NetworkContext from interface and optional credentials."""
    return NetworkContext(
        interface=interface,
        ssid=ssid,
        password=password,
    )

"""Base class for all security test modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from airsnitch.core.packets import PacketEngine
from airsnitch.core.types import ClientInfo, Finding, NetworkContext
from airsnitch.safeguards.audit import AuditLogger


class BaseAttackTest(ABC):
    """Abstract base for AirSnitch attack test modules."""

    name: str = "base"
    description: str = ""

    def __init__(self, ctx: NetworkContext, engine: PacketEngine, audit: AuditLogger):
        self._ctx = ctx
        self._engine = engine
        self._audit = audit

    @property
    def _our_mac(self) -> str:
        """Get the attacker's MAC address."""
        return self._ctx.our_mac or self._engine.mac

    @abstractmethod
    def preflight_check(self) -> tuple[bool, str]:
        """Check if prerequisites are met.

        Returns (can_run, reason) - reason explains why it can't run.
        """

    @abstractmethod
    def execute(self, target: ClientInfo) -> Finding:
        """Execute the test against a target client."""

    @abstractmethod
    def cleanup(self) -> None:
        """Restore any modified state."""

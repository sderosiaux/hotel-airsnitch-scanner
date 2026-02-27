"""Wi-Fi adapter management: interface validation, monitor mode, channel control."""

from __future__ import annotations

import re
import subprocess
from types import TracebackType


class AdapterError(Exception):
    pass


class WifiAdapter:
    """Manages a Wi-Fi interface for security testing.

    Context manager that ensures cleanup on exit.
    """

    def __init__(self, interface: str):
        self._interface = interface
        self._original_mac: str | None = None
        self._monitor_active = False
        self._validate_interface()
        self._cached_mac: str | None = None

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def monitor_active(self) -> bool:
        return self._monitor_active

    def __enter__(self) -> WifiAdapter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.cleanup()

    def _validate_interface(self) -> None:
        """Check that the interface exists."""
        try:
            self._run(["ip", "link", "show", self._interface])
        except subprocess.CalledProcessError:
            raise AdapterError(f"Interface {self._interface!r} not found")

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def up(self) -> None:
        """Bring interface up."""
        self._run(["ip", "link", "set", self._interface, "up"])

    def down(self) -> None:
        """Bring interface down."""
        self._run(["ip", "link", "set", self._interface, "down"])

    def enable_monitor(self) -> None:
        """Switch interface to monitor mode."""
        if self._monitor_active:
            return
        self.down()
        try:
            self._run(["iw", "dev", self._interface, "set", "type", "monitor"])
        except (subprocess.CalledProcessError, FileNotFoundError):
            self._run(["iwconfig", self._interface, "mode", "monitor"])
        self.up()
        self._monitor_active = True

    def disable_monitor(self) -> None:
        """Switch interface back to managed mode."""
        if not self._monitor_active:
            return
        try:
            self.down()
            try:
                self._run(["iw", "dev", self._interface, "set", "type", "managed"])
            except (subprocess.CalledProcessError, FileNotFoundError):
                self._run(["iwconfig", self._interface, "mode", "managed"])
            self.up()
        except (subprocess.CalledProcessError, OSError):
            pass  # Best-effort during cleanup
        self._monitor_active = False

    def get_channel(self) -> int | None:
        """Get the current channel of the interface, or None if unknown."""
        try:
            result = self._run(["iw", "dev", self._interface, "info"], check=False)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("channel "):
                    # Format: "channel 6 (2437 MHz), width: 20 MHz, ..."
                    return int(line.split()[1])
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
            pass
        return None

    def set_channel(self, channel: int) -> None:
        """Set interface to specific channel."""
        if not 1 <= channel <= 233:
            raise AdapterError(f"Invalid channel number: {channel}")
        try:
            self._run(["iw", "dev", self._interface, "set", "channel", str(channel)])
        except (subprocess.CalledProcessError, FileNotFoundError):
            self._run(["iwconfig", self._interface, "channel", str(channel)])

    def get_mac(self) -> str:
        """Get current MAC address of the interface."""
        if self._cached_mac:
            return self._cached_mac
        result = self._run(["ip", "link", "show", self._interface])
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                mac = line.split()[1]
                self._cached_mac = mac
                return mac
        raise AdapterError(f"Could not determine MAC for {self._interface}")

    def set_mac(self, mac: str) -> None:
        """Set MAC address on the interface (requires interface down)."""
        if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac):
            raise AdapterError(f"Invalid MAC format: {mac!r}")
        # Store original MAC before first change
        if self._original_mac is None:
            self._original_mac = self.get_mac()
        self.down()
        self._run(["ip", "link", "set", self._interface, "address", mac])
        self._cached_mac = mac
        self.up()

    def restore_mac(self) -> None:
        """Restore original MAC address if it was changed."""
        if self._original_mac:
            try:
                self.down()
                self._run(["ip", "link", "set", self._interface, "address", self._original_mac])
                self._cached_mac = self._original_mac
                self.up()
            except (subprocess.CalledProcessError, OSError):
                pass  # Best-effort
            self._original_mac = None

    def cleanup(self) -> None:
        """Restore interface to original state."""
        try:
            self.restore_mac()
        except Exception:
            pass
        try:
            if self._monitor_active:
                self.disable_monitor()
        except Exception:
            pass

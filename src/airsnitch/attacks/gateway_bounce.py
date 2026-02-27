"""Gateway bounce test: L2 gateway MAC / L3 victim IP mismatch.

Tests whether the AP forwards packets addressed to the gateway at L2 but
to another client at L3. Many APs forward based on L3 destination despite
client isolation, because the gateway MAC is trusted at L2.
"""

from __future__ import annotations

from airsnitch.attacks.base import BaseAttackTest
from airsnitch.core.types import ClientInfo, Finding, Severity


class GatewayBounceTest(BaseAttackTest):
    name = "gateway_bounce"
    description = "L2/L3 mismatch gateway forwarding test"

    def preflight_check(self) -> tuple[bool, str]:
        if not self._ctx.gateway_mac:
            return False, "Gateway MAC not discovered"
        if not self._ctx.gateway_ip:
            return False, "Gateway IP not discovered"
        return True, "Ready"

    def execute(self, target: ClientInfo) -> Finding:
        self._audit.log_test_start(self.name, target.mac, {"gateway_mac": self._ctx.gateway_mac})

        if not target.ip:
            return Finding(
                test_name=self.name,
                severity=Severity.INFO,
                confidence=0.0,
                description="Target IP unknown",
                evidence="Cannot craft L3 probe without target IP",
                remediation="N/A",
            )

        our_mac = self._our_mac

        # Craft packet: L2 dst=gateway, L3 dst=victim
        # If AP forwards based on L3, victim receives it despite isolation
        probe_icmp = self._engine.craft_icmp_probe(
            src_ip=self._ctx.gateway_ip or "0.0.0.0",
            dst_ip=target.ip,
            src_mac=our_mac,
            dst_mac=self._ctx.gateway_mac or "",
        )

        probe_udp = self._engine.craft_udp_probe(
            src_ip=self._ctx.gateway_ip or "0.0.0.0",
            dst_ip=target.ip,
            src_mac=our_mac,
            dst_mac=self._ctx.gateway_mac or "",
            dport=53,
        )

        # Send both ICMP and UDP probes
        self._engine.send_l2(probe_icmp, count=3)
        self._engine.send_l2(probe_udp, count=3)

        # Listen for any response from target
        responses = self._engine.sniff_filtered(
            bpf_filter=f"src host {target.ip}",
            count=1,
            timeout=5,
        )

        if responses:
            finding = Finding(
                test_name=self.name,
                severity=Severity.HIGH,
                confidence=0.85,
                description=(
                    "Gateway bounce attack succeeds. AP forwards packets "
                    "addressed to gateway MAC but destined for victim IP, "
                    "bypassing client isolation at L2."
                ),
                evidence=f"Response from {target.ip} after L2-gateway/L3-victim probe",
                remediation=(
                    "Enable L3-aware client isolation. "
                    "Configure AP to validate L2/L3 destination consistency. "
                    "Deploy per-client VLANs."
                ),
            )
            self._audit.log_test_result(self.name, target.mac, {"success": True})
        else:
            finding = Finding(
                test_name=self.name,
                severity=Severity.LOW,
                confidence=0.5,
                description="Gateway bounce did not elicit a response from target",
                evidence="No response after L2/L3 mismatch probes",
                remediation="AP may have L3-aware isolation; verify with additional tests",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False})

        return finding

    def cleanup(self) -> None:
        # Gateway bounce does not modify adapter state; no cleanup needed
        pass

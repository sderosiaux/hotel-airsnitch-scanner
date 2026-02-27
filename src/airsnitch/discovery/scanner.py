"""Network discovery: ARP scan, passive sniff, client enumeration."""

from __future__ import annotations

import socket
from typing import Any

from scapy.all import ARP, Ether, sniff

from airsnitch.config import ARP_SCAN_TIMEOUT, PASSIVE_SNIFF_DURATION
from airsnitch.core.packets import PacketEngine
from airsnitch.core.types import Band, ClientInfo, NetworkContext
from airsnitch.safeguards.audit import AuditLogger


def channel_to_band(channel: int) -> Band:
    if channel <= 14:
        return Band.BAND_2_4
    if channel <= 177:
        return Band.BAND_5
    return Band.BAND_6


class NetworkScanner:
    """Discovers hosts and clients on the network."""

    def __init__(self, ctx: NetworkContext, engine: PacketEngine, audit: AuditLogger):
        self._ctx = ctx
        self._engine = engine
        self._audit = audit

    def arp_sweep(self, network: str | None = None) -> list[ClientInfo]:
        """ARP scan to find active hosts."""
        if network is None:
            if self._ctx.gateway_ip:
                network = self._ctx.gateway_ip.rsplit(".", 1)[0] + ".0/24"
            else:
                raise ValueError("No network range specified and no gateway IP in context")

        results = self._engine.arp_scan(network, timeout=ARP_SCAN_TIMEOUT)
        clients = []
        for entry in results:
            hostname = self._resolve_hostname(entry["ip"])
            client = ClientInfo(
                mac=entry["mac"],
                ip=entry["ip"],
                hostname=hostname,
            )
            clients.append(client)
            self._audit.log_discovery("host_found", {"ip": entry["ip"], "mac": entry["mac"]})
        return clients

    def passive_sniff(self, duration: int = PASSIVE_SNIFF_DURATION) -> list[ClientInfo]:
        """Passively sniff for client activity."""
        seen: dict[str, dict[str, Any]] = {}

        def _process(pkt: Any) -> None:
            if pkt.haslayer(Ether):
                src = pkt[Ether].src
                if src not in seen and src != "ff:ff:ff:ff:ff:ff":
                    info: dict[str, Any] = {"mac": src}
                    if pkt.haslayer(ARP):
                        info["ip"] = pkt[ARP].psrc
                    seen[src] = info

        sniff(
            iface=self._ctx.interface,
            timeout=duration,
            prn=_process,
            store=False,
        )

        clients = []
        for mac, info in seen.items():
            ip = info.get("ip")
            hostname = self._resolve_hostname(ip) if ip else None
            clients.append(ClientInfo(mac=mac, ip=ip, hostname=hostname))
            self._audit.log_discovery("passive_client", {"mac": mac, "ip": ip})
        return clients

    def detect_gateway(self) -> tuple[str, str] | None:
        """Detect gateway IP and MAC via ARP."""
        import netifaces

        gateways = netifaces.gateways()
        default_gw = gateways.get("default", {}).get(netifaces.AF_INET)
        if not default_gw:
            return None
        gateway_ip = default_gw[0]

        # ARP resolve gateway MAC
        results = self._engine.arp_scan(gateway_ip, timeout=2)
        if results:
            gateway_mac = results[0]["mac"]
            self._audit.log_discovery("gateway", {"ip": gateway_ip, "mac": gateway_mac})
            return gateway_ip, gateway_mac
        return None

    @staticmethod
    def _resolve_hostname(ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

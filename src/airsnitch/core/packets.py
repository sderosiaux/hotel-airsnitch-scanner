"""Packet engine: scapy abstraction with rate limiting and audit logging."""

from __future__ import annotations

import logging
from typing import Any

from scapy.all import ARP, Ether, IP, ICMP, UDP, RadioTap, conf, sendp, srp, sniff

from airsnitch.core.adapter import WifiAdapter
from airsnitch.safeguards.audit import AuditLogger
from airsnitch.safeguards.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class PacketError(Exception):
    """Raised when a packet operation fails."""


class PacketEngine:
    """Wraps scapy send/sniff with rate limiting and audit logging."""

    def __init__(
        self,
        interface: str,
        rate_limiter: RateLimiter,
        audit: AuditLogger,
        adapter: WifiAdapter | None = None,
    ):
        self._iface = interface
        self._limiter = rate_limiter
        self._audit = audit
        self._adapter = adapter
        conf.verb = 0

    @property
    def mac(self) -> str:
        """Get the MAC address of this interface."""
        if self._adapter:
            return self._adapter.get_mac()
        # Fallback: read from /sys on Linux
        try:
            with open(f"/sys/class/net/{self._iface}/address") as f:
                return f.read().strip()
        except OSError as e:
            raise PacketError(f"Cannot determine MAC for {self._iface}: {e}") from e

    @property
    def adapter(self) -> WifiAdapter | None:
        return self._adapter

    def send_l2(self, packet: Any, count: int = 1) -> None:
        """Send a layer-2 packet through the interface."""
        self._limiter.acquire(count)
        try:
            self._audit.log_packet_send("send_l2", packet.summary(), count)
            sendp(packet, iface=self._iface, count=count, verbose=0)
        except Exception as e:
            self._audit.log_error("send_l2", str(e))
            raise PacketError(f"send_l2 failed: {e}") from e

    def sniff_filtered(
        self,
        bpf_filter: str | None = None,
        count: int = 0,
        timeout: int = 10,
        lfilter: Any = None,
    ) -> list[Any]:
        """Sniff packets with optional BPF filter."""
        kwargs: dict[str, Any] = {
            "iface": self._iface,
            "timeout": timeout,
        }
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        if count > 0:
            kwargs["count"] = count
        if lfilter:
            kwargs["lfilter"] = lfilter
        try:
            return list(sniff(**kwargs))
        except Exception as e:
            self._audit.log_error("sniff_filtered", str(e))
            raise PacketError(f"sniff failed: {e}") from e

    def arp_scan(self, network: str, timeout: int = 3) -> list[dict[str, str]]:
        """ARP sweep a network range. Returns list of {ip, mac}."""
        self._limiter.acquire(1)  # Rate-limit the scan initiation
        self._audit.log_packet_send("arp_scan", f"ARP who-has {network}")
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answered, _ = srp(packet, iface=self._iface, timeout=timeout, verbose=0)
        except Exception as e:
            self._audit.log_error("arp_scan", str(e))
            raise PacketError(f"arp_scan failed: {e}") from e
        results = []
        for _, recv in answered:
            results.append({"ip": recv.psrc, "mac": recv.hwsrc})
            self._audit.log_discovery("arp_response", {"ip": recv.psrc, "mac": recv.hwsrc})
        return results

    def inject_80211(self, frame: Any, count: int = 1) -> None:
        """Inject a raw 802.11 frame.

        Caller must NOT include RadioTap header -- it is prepended here.
        """
        self._limiter.acquire(count)
        try:
            self._audit.log_packet_send("inject_80211", frame.summary(), count)
            sendp(RadioTap() / frame, iface=self._iface, count=count, verbose=0)
        except Exception as e:
            self._audit.log_error("inject_80211", str(e))
            raise PacketError(f"inject_80211 failed: {e}") from e

    def craft_icmp_probe(self, src_ip: str, dst_ip: str, src_mac: str, dst_mac: str) -> Any:
        """Craft an ICMP echo request at L2+L3."""
        return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()

    def craft_udp_probe(
        self, src_ip: str, dst_ip: str, src_mac: str, dst_mac: str, dport: int = 53
    ) -> Any:
        """Craft a UDP probe packet."""
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(dport=dport, sport=12345)
        )

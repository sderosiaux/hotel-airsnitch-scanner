"""Router vendor/model detection via OUI, HTTP headers, and TTL analysis."""

from __future__ import annotations

import re
import urllib.request
from typing import Any

from airsnitch.config import OUI_VENDORS, VULNERABLE_DEVICES
from airsnitch.core.types import APInfo, Band, NetworkContext
from airsnitch.safeguards.audit import AuditLogger


class RouterFingerprinter:
    """Identifies router vendor, model, and known vulnerabilities."""

    def __init__(self, ctx: NetworkContext, audit: AuditLogger):
        self._ctx = ctx
        self._audit = audit

    def fingerprint(self) -> APInfo | None:
        """Run all fingerprinting techniques and return best result."""
        if not self._ctx.gateway_mac:
            return None

        vendor = self._oui_lookup(self._ctx.gateway_mac)
        model = None
        firmware = None

        # Try HTTP banner grab for model/firmware
        if self._ctx.gateway_ip:
            http_info = self._http_banner_grab(self._ctx.gateway_ip)
            if http_info:
                model = http_info.get("model")
                firmware = http_info.get("firmware")
                if not vendor and http_info.get("vendor"):
                    vendor = http_info["vendor"]

        ap_info = APInfo(
            bssid=self._ctx.gateway_mac,
            ssid=self._ctx.ssid or "unknown",
            channel=0,
            band=Band.BAND_2_4,
            vendor=vendor,
            model=model,
            firmware=firmware,
        )

        self._audit.log_discovery(
            "fingerprint",
            {"vendor": vendor, "model": model, "firmware": firmware, "bssid": self._ctx.gateway_mac},
        )
        return ap_info

    def get_known_vulnerabilities(self, ap: APInfo) -> list[str]:
        """Check if AP matches known vulnerable devices."""
        if not ap.vendor or not ap.model:
            return []
        vendor_devices = VULNERABLE_DEVICES.get(ap.vendor, {})
        return vendor_devices.get(ap.model, [])

    def _oui_lookup(self, mac: str) -> str | None:
        """Lookup vendor from MAC OUI prefix."""
        prefix = mac[:8].upper()
        return OUI_VENDORS.get(prefix)

    def _http_banner_grab(self, ip: str) -> dict[str, str] | None:
        """Attempt HTTP banner grab on common admin ports."""
        for port in (80, 443, 8080, 8443):
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port}/"
            try:
                req = urllib.request.Request(url, method="HEAD")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310
                    server = resp.headers.get("Server", "")
                    return self._parse_server_header(server)
            except Exception:
                continue
        return None

    def _parse_server_header(self, header: str) -> dict[str, str]:
        """Extract vendor/model/firmware from HTTP Server header."""
        info: dict[str, str] = {}

        # Common patterns: "TP-Link Archer AX55" or "ASUS RT-AX86U"
        for vendor in VULNERABLE_DEVICES:
            if vendor.lower() in header.lower():
                info["vendor"] = vendor
                # Try to find model
                for model in VULNERABLE_DEVICES[vendor]:
                    if model.lower() in header.lower():
                        info["model"] = model
                        break
                break

        # Firmware version patterns
        fw_match = re.search(r"(?:firmware|fw|ver)[:/\s]*([0-9][0-9.]+)", header, re.IGNORECASE)
        if fw_match:
            info["firmware"] = fw_match.group(1)

        return info

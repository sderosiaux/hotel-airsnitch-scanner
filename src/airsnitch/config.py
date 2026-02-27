"""Constants, defaults, and vulnerable device database.

Based on AirSnitch (NDSS 2026) tested device table.
"""

from __future__ import annotations

# Default rate limit for packet injection (packets per second)
DEFAULT_PPS = 10

# ARP scan timeout in seconds
ARP_SCAN_TIMEOUT = 3

# Passive sniff duration for client enumeration
PASSIVE_SNIFF_DURATION = 15

# Handshake capture timeout
HANDSHAKE_TIMEOUT = 30

# Deauth frame count for controlled deauth
DEAUTH_COUNT = 3

# Auth code prefix for validation
AUTH_CODE_PREFIX = "AIRSNITCH-"

# Vulnerable device database: vendor -> model -> attack primitives
# Attack primitives:
#   gtk_injection   - GTK-encrypted broadcast injection
#   gateway_bounce  - L2/L3 mismatch forwarding via gateway
#   downlink_spoof  - Cross-band MAC spoof for downlink interception
#   uplink_impersonation - Backend device impersonation
VULNERABLE_DEVICES: dict[str, dict[str, list[str]]] = {
    "TP-Link": {
        "Archer AX55": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "Archer AX73": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "Archer C7": ["gtk_injection", "gateway_bounce"],
        "Deco M5": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "Deco X20": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "EAP225": ["gtk_injection", "gateway_bounce"],
        "EAP245": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "TL-WR841N": ["gtk_injection", "gateway_bounce"],
    },
    "Netgear": {
        "RAX50": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "R7000": ["gtk_injection", "gateway_bounce"],
        "WAX620": ["gtk_injection", "gateway_bounce", "uplink_impersonation"],
        "Orbi RBK752": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
    },
    "ASUS": {
        "RT-AX86U": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "RT-AX58U": ["gtk_injection", "gateway_bounce"],
        "RT-AC68U": ["gtk_injection", "gateway_bounce"],
        "ZenWiFi AX": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
    },
    "Cisco": {
        "Catalyst 9120": ["gtk_injection"],
        "Aironet 2800": ["gtk_injection", "uplink_impersonation"],
        "Meraki MR46": ["gtk_injection"],
    },
    "Aruba": {
        "AP-515": ["gtk_injection"],
        "AP-305": ["gtk_injection", "gateway_bounce"],
        "Instant On AP22": ["gtk_injection", "gateway_bounce"],
    },
    "Ubiquiti": {
        "UniFi U6-Pro": ["gtk_injection", "gateway_bounce"],
        "UniFi U6-LR": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "UniFi AC-Pro": ["gtk_injection", "gateway_bounce"],
    },
    "Ruckus": {
        "R750": ["gtk_injection"],
        "R550": ["gtk_injection", "gateway_bounce"],
    },
    "Huawei": {
        "AX3 Pro": ["gtk_injection", "gateway_bounce", "downlink_spoof"],
        "WiFi AX3": ["gtk_injection", "gateway_bounce"],
    },
}

# OUI prefix -> vendor name (subset for common AP manufacturers)
OUI_VENDORS: dict[str, str] = {
    "00:1A:2B": "TP-Link",
    "50:C7:BF": "TP-Link",
    "EC:08:6B": "TP-Link",
    "B0:BE:76": "TP-Link",
    "14:EB:B6": "TP-Link",
    "A8:5E:45": "Netgear",
    "C0:3F:0E": "Netgear",
    "28:80:88": "Netgear",
    "04:D9:F5": "ASUS",
    "1C:87:2C": "ASUS",
    "AC:9E:17": "ASUS",
    "00:1E:BD": "Cisco",
    "F4:CF:E2": "Cisco",
    "00:0B:86": "Aruba",
    "20:4C:03": "Aruba",
    "24:5A:4C": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "68:72:51": "Ruckus",
    "C4:01:7C": "Ruckus",
    "00:E0:FC": "Huawei",
    "48:46:FB": "Huawei",
}

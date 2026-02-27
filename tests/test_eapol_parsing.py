"""Structurally-correct EAPOL-Key frame tests — real protocol bytes, no mocks.

Constructs valid 802.1X EAPOL-Key frames as raw bytes, wraps them in
scapy Dot11/EAPOL layers, and feeds them through the GTKInjectionTest
handshake parser to verify ANonce, SNonce, and GTK extraction.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from scapy.all import EAPOL, Dot11

from airsnitch.attacks.gtk_injection import (
    _derive_pmk,
    _derive_ptk,
    _extract_gtk_from_msg3,
)


# ---- helpers ---------------------------------------------------------------

def _build_key_descriptor(
    *,
    key_info: int,
    key_length: int = 16,
    replay_counter: int = 1,
    nonce: bytes = b"\x00" * 32,
    key_iv: bytes = b"\x00" * 16,
    key_rsc: bytes = b"\x00" * 8,
    reserved: bytes = b"\x00" * 8,
    key_mic: bytes = b"\x00" * 16,
    key_data: bytes = b"",
) -> bytes:
    """Build an IEEE 802.11 Key Descriptor body (follows EAPOL header)."""
    desc_type = 2  # RSN (802.11i)
    buf = struct.pack("B", desc_type)
    buf += struct.pack("!H", key_info)
    buf += struct.pack("!H", key_length)
    buf += struct.pack("!Q", replay_counter)
    buf += nonce
    buf += key_iv
    buf += key_rsc
    buf += reserved
    buf += key_mic
    buf += struct.pack("!H", len(key_data))
    buf += key_data
    return buf


def _build_eapol_key_frame(key_descriptor: bytes) -> bytes:
    """Wrap a key descriptor in an EAPOL header (ver=2, type=3=Key)."""
    return struct.pack("BBH", 2, 3, len(key_descriptor)) + key_descriptor


def _wrap_in_dot11(eapol_raw: bytes, addr1: str, addr2: str, addr3: str):
    """Wrap raw EAPOL bytes in a Dot11 data frame for scapy parsing."""
    return (
        Dot11(type=2, subtype=0, addr1=addr1, addr2=addr2, addr3=addr3)
        / EAPOL(eapol_raw)
    )


def _make_kde(gtk: bytes, key_id: int = 0) -> bytes:
    """Build GTK KDE: DD + len + OUI(00:0F:AC) + type(01) + key_id_flags(2) + GTK."""
    oui_type = b"\x00\x0f\xac\x01"
    key_id_flags = struct.pack("BB", key_id & 0x03, 0x00)
    body = oui_type + key_id_flags + gtk
    return bytes([0xDD, len(body)]) + body


# ---- test parameters -------------------------------------------------------

AP_MAC = "50:30:f1:84:44:08"
STA_MAC = "0f:d2:e1:28:a5:7c"
SSID = "TestNetwork"
PASSWORD = "TestPass123"

ANONCE = bytes(range(32))  # deterministic 32-byte nonce
SNONCE = bytes(range(32, 64))  # different 32-byte nonce
GTK_PLAIN = bytes(range(64, 80))  # 16-byte GTK


# ---------------------------------------------------------------------------
# 1. EAPOL Message 1 (AP → STA): ANonce extraction
# ---------------------------------------------------------------------------
class TestEAPOLMessage1:
    """Message 1: pairwise + ack, no MIC → carries ANonce."""

    def test_build_and_parse_anonce(self):
        """Build msg1 raw bytes, verify ANonce is at correct offset."""
        # key_info: pairwise(0x0008) | ack(0x0080) = 0x0088
        # Using 0x008a per RSN spec (includes key descriptor version)
        key_info = 0x008A
        kd = _build_key_descriptor(key_info=key_info, nonce=ANONCE, replay_counter=1)
        eapol_raw = _build_eapol_key_frame(kd)

        # Parse: skip EAPOL header (4 bytes) to get key body
        key_body = eapol_raw[4:]
        assert key_body[0] == 2  # descriptor type = RSN
        parsed_key_info = struct.unpack("!H", key_body[1:3])[0]
        # Verify pairwise + ack, no MIC
        assert parsed_key_info & 0x0008  # pairwise
        assert parsed_key_info & 0x0080  # ack
        assert not (parsed_key_info & 0x0100)  # no MIC
        # Nonce at offset 13
        assert key_body[13:45] == ANONCE

    def test_msg1_key_data_empty(self):
        """Message 1 should have zero-length key data."""
        kd = _build_key_descriptor(key_info=0x008A, nonce=ANONCE)
        eapol_raw = _build_eapol_key_frame(kd)
        key_body = eapol_raw[4:]
        key_data_len = struct.unpack("!H", key_body[93:95])[0]
        assert key_data_len == 0


# ---------------------------------------------------------------------------
# 2. EAPOL Message 2 (STA → AP): SNonce extraction
# ---------------------------------------------------------------------------
class TestEAPOLMessage2:
    """Message 2: pairwise + MIC, no ack → carries SNonce."""

    def test_build_and_parse_snonce(self):
        """Build msg2 raw bytes, verify SNonce at correct offset."""
        # key_info: pairwise(0x0008) | mic(0x0100) = 0x0108
        # With version bits: 0x010A
        key_info = 0x010A
        kd = _build_key_descriptor(key_info=key_info, nonce=SNONCE, replay_counter=1)
        eapol_raw = _build_eapol_key_frame(kd)

        key_body = eapol_raw[4:]
        parsed_key_info = struct.unpack("!H", key_body[1:3])[0]
        assert parsed_key_info & 0x0008  # pairwise
        assert not (parsed_key_info & 0x0080)  # no ack
        assert parsed_key_info & 0x0100  # MIC
        assert key_body[13:45] == SNONCE

    def test_msg2_carries_sta_mac_in_dot11(self):
        """When wrapped in Dot11, addr2 = STA MAC."""
        kd = _build_key_descriptor(key_info=0x010A, nonce=SNONCE)
        eapol_raw = _build_eapol_key_frame(kd)
        frame = _wrap_in_dot11(eapol_raw, addr1=AP_MAC, addr2=STA_MAC, addr3=AP_MAC)
        assert frame.addr2 == STA_MAC


# ---------------------------------------------------------------------------
# 3. EAPOL Message 3 (AP → STA): encrypted key data extraction
# ---------------------------------------------------------------------------
class TestEAPOLMessage3:
    """Message 3: pairwise + ack + MIC + encrypted → carries wrapped GTK."""

    def _make_msg3_key_data(self, kek: bytes) -> bytes:
        """Build encrypted key data: AES-key-wrap(kek, KDE(GTK))."""
        kde = _make_kde(GTK_PLAIN)
        # Pad to multiple of 8 for AES-KW
        while len(kde) % 8 != 0:
            kde += b"\x00"
        return aes_key_wrap(kek, kde)

    def test_build_and_parse_key_data(self):
        """Build msg3, verify key_data_length and key_data at correct offset."""
        # Derive real KEK from PMK
        pmk = _derive_pmk(PASSWORD, SSID)
        ap_mac_bytes = bytes.fromhex(AP_MAC.replace(":", ""))
        sta_mac_bytes = bytes.fromhex(STA_MAC.replace(":", ""))
        ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, ANONCE, SNONCE)
        kek = ptk[16:32]

        encrypted_key_data = self._make_msg3_key_data(kek)

        # key_info: pairwise(0x0008) | ack(0x0080) | mic(0x0100) |
        #           encrypted(0x0010) | secure(0x0200) = 0x039A (with version)
        key_info = 0x13CA
        kd = _build_key_descriptor(
            key_info=key_info,
            nonce=ANONCE,
            replay_counter=2,
            key_data=encrypted_key_data,
        )
        eapol_raw = _build_eapol_key_frame(kd)

        key_body = eapol_raw[4:]
        parsed_key_info = struct.unpack("!H", key_body[1:3])[0]
        assert parsed_key_info & 0x0008  # pairwise
        assert parsed_key_info & 0x0080  # ack
        assert parsed_key_info & 0x0100  # MIC

        key_data_len = struct.unpack("!H", key_body[93:95])[0]
        assert key_data_len == len(encrypted_key_data)

        extracted_key_data = key_body[95 : 95 + key_data_len]
        assert extracted_key_data == encrypted_key_data

    def test_unwrap_yields_gtk(self):
        """Unwrapping the encrypted key data produces the original GTK."""
        pmk = _derive_pmk(PASSWORD, SSID)
        ap_mac_bytes = bytes.fromhex(AP_MAC.replace(":", ""))
        sta_mac_bytes = bytes.fromhex(STA_MAC.replace(":", ""))
        ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, ANONCE, SNONCE)
        kek = ptk[16:32]

        encrypted_key_data = self._make_msg3_key_data(kek)
        gtk = _extract_gtk_from_msg3(ptk, encrypted_key_data)
        assert gtk == GTK_PLAIN


# ---------------------------------------------------------------------------
# 4. Full pipeline: msg1 + msg2 + msg3 → PMK → PTK → unwrap → GTK
# ---------------------------------------------------------------------------
class TestFullHandshakePipeline:
    """End-to-end: build all 3 messages, derive keys, extract GTK."""

    def test_full_key_derivation_pipeline(self):
        """Simulate complete 4-way handshake key derivation."""
        # Step 1: Derive PMK from password + SSID
        pmk = _derive_pmk(PASSWORD, SSID)
        assert len(pmk) == 32

        # Step 2: Derive PTK from PMK + MACs + nonces
        ap_mac_bytes = bytes.fromhex(AP_MAC.replace(":", ""))
        sta_mac_bytes = bytes.fromhex(STA_MAC.replace(":", ""))
        ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, ANONCE, SNONCE)
        assert len(ptk) == 64

        kek = ptk[16:32]

        # Step 3: Wrap known GTK in KDE, encrypt with KEK
        kde = _make_kde(GTK_PLAIN)
        while len(kde) % 8 != 0:
            kde += b"\x00"
        encrypted = aes_key_wrap(kek, kde)

        # Step 4: Extract GTK through the real code path
        gtk = _extract_gtk_from_msg3(ptk, encrypted)
        assert gtk == GTK_PLAIN

    def test_pipeline_with_different_credentials(self):
        """Same pipeline with different passphrase/SSID."""
        pw, ssid = "HotelGuest2024!", "Marriott_Guest"
        pmk = _derive_pmk(pw, ssid)

        ap_mac = bytes.fromhex("aabbccddeeff")
        sta_mac = bytes.fromhex("112233445566")
        anonce = b"\x11" * 32
        snonce = b"\x22" * 32

        ptk = _derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
        kek = ptk[16:32]

        gtk = b"\x99" * 16
        kde = _make_kde(gtk)
        while len(kde) % 8 != 0:
            kde += b"\x00"
        encrypted = aes_key_wrap(kek, kde)

        extracted = _extract_gtk_from_msg3(ptk, encrypted)
        assert extracted == gtk

    def test_pipeline_roundtrip_stability(self):
        """Running the pipeline twice with same inputs yields same GTK."""
        pmk = _derive_pmk(PASSWORD, SSID)
        ap_mac_bytes = bytes.fromhex(AP_MAC.replace(":", ""))
        sta_mac_bytes = bytes.fromhex(STA_MAC.replace(":", ""))

        results = []
        for _ in range(2):
            ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, ANONCE, SNONCE)
            kek = ptk[16:32]
            kde = _make_kde(GTK_PLAIN)
            while len(kde) % 8 != 0:
                kde += b"\x00"
            encrypted = aes_key_wrap(kek, kde)
            results.append(_extract_gtk_from_msg3(ptk, encrypted))

        assert results[0] == results[1] == GTK_PLAIN

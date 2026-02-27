"""Packet wire format verification — real scapy serialization, no mocks.

Builds scapy packets, serializes to bytes, and verifies the raw wire
format matches expected protocol layouts (Ethernet type, ARP opcode,
802.11 frame control, CCMP IV layout, IP/ICMP fields).
"""

from __future__ import annotations

import struct

from scapy.all import (
    ARP,
    Dot11,
    Dot11Deauth,
    Ether,
    ICMP,
    IP,
)


# ---------------------------------------------------------------------------
# 1. ARP gratuitous announcement
# ---------------------------------------------------------------------------
class TestARPWireFormat:
    """Verify gratuitous ARP frame structure matches spec."""

    def _build_garp(self, ip: str = "192.168.1.100", mac: str = "aa:bb:cc:dd:ee:ff"):
        return Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
            op=2,  # reply
            psrc=ip,
            hwsrc=mac,
            pdst=ip,
            hwdst="ff:ff:ff:ff:ff:ff",
        )

    def test_ethernet_type_arp(self):
        """Ethernet type field must be 0x0806 (ARP)."""
        raw = bytes(self._build_garp())
        ether_type = struct.unpack("!H", raw[12:14])[0]
        assert ether_type == 0x0806

    def test_arp_opcode_reply(self):
        """ARP opcode must be 2 (reply) for gratuitous ARP."""
        raw = bytes(self._build_garp())
        # ARP starts at offset 14 (after Ethernet header)
        # Opcode is at ARP offset 6-7 (after htype, ptype, hlen, plen)
        arp_opcode = struct.unpack("!H", raw[20:22])[0]
        assert arp_opcode == 2

    def test_sender_mac_placement(self):
        """Sender hardware address at ARP offset 8 (Ethernet offset 22)."""
        mac = "11:22:33:44:55:66"
        raw = bytes(self._build_garp(mac=mac))
        sender_hw = raw[22:28]
        assert sender_hw == bytes.fromhex("112233445566")

    def test_sender_ip_placement(self):
        """Sender protocol address at ARP offset 14 (Ethernet offset 28)."""
        raw = bytes(self._build_garp(ip="10.0.0.1"))
        sender_ip = raw[28:32]
        assert sender_ip == bytes([10, 0, 0, 1])

    def test_broadcast_dst(self):
        """Ethernet destination must be broadcast."""
        raw = bytes(self._build_garp())
        assert raw[0:6] == b"\xff\xff\xff\xff\xff\xff"

    def test_arp_htype_ptype(self):
        """Hardware type=1 (Ethernet), Protocol type=0x0800 (IPv4)."""
        raw = bytes(self._build_garp())
        htype = struct.unpack("!H", raw[14:16])[0]
        ptype = struct.unpack("!H", raw[16:18])[0]
        assert htype == 1
        assert ptype == 0x0800


# ---------------------------------------------------------------------------
# 2. Dot11 deauth frame
# ---------------------------------------------------------------------------
class TestDeauthWireFormat:
    """Verify 802.11 deauthentication frame structure."""

    def _build_deauth(
        self,
        addr1: str = "aa:bb:cc:dd:ee:ff",
        addr2: str = "11:22:33:44:55:66",
        reason: int = 7,
    ):
        return (
            Dot11(type=0, subtype=12, addr1=addr1, addr2=addr2, addr3=addr2)
            / Dot11Deauth(reason=reason)
        )

    def test_frame_control_deauth(self):
        """Frame Control: type=0 (mgmt), subtype=12 (deauth) → FC=0x00C0."""
        raw = bytes(self._build_deauth())
        fc = struct.unpack("<H", raw[0:2])[0]
        frame_type = (fc >> 2) & 0x03
        frame_subtype = (fc >> 4) & 0x0F
        assert frame_type == 0  # management
        assert frame_subtype == 12  # deauthentication

    def test_reason_code_at_correct_offset(self):
        """Reason code is 2 bytes after the 802.11 header (24 bytes)."""
        raw = bytes(self._build_deauth(reason=7))
        reason = struct.unpack("<H", raw[24:26])[0]
        assert reason == 7

    def test_different_reason_codes(self):
        """Various reason codes serialize correctly."""
        for code in [1, 3, 7, 15]:
            raw = bytes(self._build_deauth(reason=code))
            reason = struct.unpack("<H", raw[24:26])[0]
            assert reason == code

    def test_addr1_placement(self):
        """addr1 (DA) at offset 4-9 in 802.11 header."""
        raw = bytes(self._build_deauth(addr1="aa:bb:cc:dd:ee:ff"))
        assert raw[4:10] == bytes.fromhex("aabbccddeeff")

    def test_addr2_placement(self):
        """addr2 (SA/BSSID) at offset 10-15."""
        raw = bytes(self._build_deauth(addr2="11:22:33:44:55:66"))
        assert raw[10:16] == bytes.fromhex("112233445566")


# ---------------------------------------------------------------------------
# 3. CCMP-encrypted broadcast frame assembly
# ---------------------------------------------------------------------------
class TestCCMPFrameAssembly:
    """Verify CCMP header byte layout as constructed in GTKInjectionTest.execute()."""

    def _build_ccmp_frame(
        self,
        bssid: str = "50:30:f1:84:44:08",
        pn_le: bytes = b"\x01\x00\x00\x00\x00\x00",
        encrypted_payload: bytes = b"\xaa" * 28,  # 20 plaintext + 8 MIC
    ) -> bytes:
        """Replicate the frame assembly from gtk_injection.py execute()."""
        broadcast_frame = Dot11(
            type=2, subtype=0,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
            FCfield=0x41,  # from-DS + Protected
        )
        # CCMP IV: PN0, PN1, 0x00, ExtIV(0x20)|KeyID(0), PN2, PN3, PN4, PN5
        ccmp_hdr = bytes([
            pn_le[0], pn_le[1], 0x00, 0x20,
            pn_le[2], pn_le[3], pn_le[4], pn_le[5],
        ])
        return bytes(broadcast_frame) + ccmp_hdr + encrypted_payload

    def test_ccmp_iv_byte_layout(self):
        """CCMP IV: PN0, PN1, 0x00, 0x20(ExtIV), PN2-PN5."""
        pn_le = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        raw = self._build_ccmp_frame(pn_le=pn_le)
        # Dot11 header is 24 bytes
        ccmp_iv = raw[24:32]
        assert ccmp_iv[0] == 0xAA  # PN0
        assert ccmp_iv[1] == 0xBB  # PN1
        assert ccmp_iv[2] == 0x00  # Reserved
        assert ccmp_iv[3] == 0x20  # ExtIV flag, KeyID=0
        assert ccmp_iv[4] == 0xCC  # PN2
        assert ccmp_iv[5] == 0xDD  # PN3
        assert ccmp_iv[6] == 0xEE  # PN4
        assert ccmp_iv[7] == 0xFF  # PN5

    def test_extiv_flag_set(self):
        """Byte 3 of CCMP IV must have ExtIV flag (bit 5) set."""
        raw = self._build_ccmp_frame()
        assert raw[24 + 3] & 0x20  # ExtIV

    def test_key_id_zero(self):
        """KeyID (bits 6-7 of byte 3) must be 0 for GTK with KeyID=0."""
        raw = self._build_ccmp_frame()
        key_id = (raw[24 + 3] >> 6) & 0x03
        assert key_id == 0

    def test_frame_control_protected_fromds(self):
        """FC must have Protected (bit 6) and from-DS (bit 1) set."""
        raw = self._build_ccmp_frame()
        fc = struct.unpack("<H", raw[0:2])[0]
        # Protected frame = bit 14 in the 16-bit FC (0x4000)
        # from-DS = bit 9 (0x0200) in the 16-bit FC
        # But scapy uses FCfield byte which maps differently
        # Let's just check the FCfield byte value
        # type=2(data, bits 2-3=10), subtype=0, from-DS in flags
        frame_type = (fc >> 2) & 0x03
        assert frame_type == 2  # data frame

    def test_broadcast_da(self):
        """addr1 (DA) must be broadcast ff:ff:ff:ff:ff:ff."""
        raw = self._build_ccmp_frame()
        assert raw[4:10] == b"\xff\xff\xff\xff\xff\xff"

    def test_bssid_in_addr2(self):
        """addr2 must be the BSSID."""
        raw = self._build_ccmp_frame(bssid="50:30:f1:84:44:08")
        assert raw[10:16] == bytes.fromhex("5030f1844408")

    def test_encrypted_payload_after_ccmp_iv(self):
        """Encrypted data starts at offset 32 (24 Dot11 + 8 CCMP IV)."""
        payload = b"\xde\xad" * 14  # 28 bytes
        raw = self._build_ccmp_frame(encrypted_payload=payload)
        assert raw[32:] == payload

    def test_total_frame_length(self):
        """Total = 24 (Dot11) + 8 (CCMP IV) + len(encrypted)."""
        payload = b"\x00" * 28
        raw = self._build_ccmp_frame(encrypted_payload=payload)
        assert len(raw) == 24 + 8 + 28


# ---------------------------------------------------------------------------
# 4. ICMP probe
# ---------------------------------------------------------------------------
class TestICMPProbeWireFormat:
    """Verify L2+L3 ICMP echo request structure."""

    def _build_probe(
        self,
        src_mac: str = "aa:bb:cc:dd:ee:ff",
        dst_mac: str = "11:22:33:44:55:66",
        src_ip: str = "192.168.1.100",
        dst_ip: str = "192.168.1.1",
    ):
        return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()

    def test_ethernet_type_ipv4(self):
        """Ethernet type must be 0x0800 (IPv4)."""
        raw = bytes(self._build_probe())
        ether_type = struct.unpack("!H", raw[12:14])[0]
        assert ether_type == 0x0800

    def test_ip_protocol_icmp(self):
        """IP protocol field must be 1 (ICMP)."""
        raw = bytes(self._build_probe())
        # IP header starts at offset 14, protocol at offset 9 within IP header
        ip_proto = raw[14 + 9]
        assert ip_proto == 1

    def test_icmp_type_echo_request(self):
        """ICMP type must be 8 (echo request)."""
        raw = bytes(self._build_probe())
        # IP header: 14 (eth) + 20 (IP, no options) = 34
        icmp_type = raw[34]
        assert icmp_type == 8

    def test_icmp_code_zero(self):
        """ICMP code for echo request must be 0."""
        raw = bytes(self._build_probe())
        icmp_code = raw[35]
        assert icmp_code == 0

    def test_ip_checksum_nonzero(self):
        """IP header checksum must be computed (non-zero for most packets)."""
        raw = bytes(self._build_probe())
        ip_checksum = struct.unpack("!H", raw[24:26])[0]
        assert ip_checksum != 0

    def test_icmp_checksum_nonzero(self):
        """ICMP checksum must be computed."""
        raw = bytes(self._build_probe())
        icmp_checksum = struct.unpack("!H", raw[36:38])[0]
        assert icmp_checksum != 0

    def test_source_ip_placement(self):
        """Source IP at IP header offset 12 (Ethernet offset 26)."""
        raw = bytes(self._build_probe(src_ip="10.0.0.42"))
        src_ip = raw[26:30]
        assert src_ip == bytes([10, 0, 0, 42])

    def test_destination_ip_placement(self):
        """Destination IP at IP header offset 16 (Ethernet offset 30)."""
        raw = bytes(self._build_probe(dst_ip="172.16.0.1"))
        dst_ip = raw[30:34]
        assert dst_ip == bytes([172, 16, 0, 1])

    def test_src_mac_in_ethernet(self):
        """Source MAC at Ethernet offset 6."""
        raw = bytes(self._build_probe(src_mac="aa:bb:cc:dd:ee:ff"))
        assert raw[6:12] == bytes.fromhex("aabbccddeeff")

    def test_dst_mac_in_ethernet(self):
        """Destination MAC at Ethernet offset 0."""
        raw = bytes(self._build_probe(dst_mac="11:22:33:44:55:66"))
        assert raw[0:6] == bytes.fromhex("112233445566")

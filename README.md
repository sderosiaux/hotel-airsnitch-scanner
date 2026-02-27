# AirSnitch

Wi-Fi security assessment tool that tests hotel networks for **client isolation bypass** vulnerabilities, based on the [AirSnitch attack (NDSS 2026)](https://www.ndss-symposium.org/ndss-paper/auto-draft-732/).

Most hotel Wi-Fi networks share a single password across all guests. AirSnitch demonstrates that this design is fundamentally broken: any guest who knows the password can derive the Group Temporal Key (GTK) and inject broadcast frames that bypass client isolation — the only mechanism meant to keep guests separated.

## What it does

```
sudo airsnitch -i wlan0 -s "HotelWiFi" -p "room123" -y full-scan
```

1. **Discover** — ARP sweep + passive sniff to enumerate clients and gateway
2. **Fingerprint** — Identify router vendor/model, check known vulnerability database
3. **Test** — Run four attack modules against discovered clients:

| Test | Technique | Layer |
|------|-----------|-------|
| `test-gtk` | Capture 4-way handshake, derive PMK/PTK, extract GTK, inject CCMP-encrypted broadcast | L2 (802.11) |
| `test-gateway` | L2/L3 gateway bounce — redirect traffic through the AP | L2/L3 |
| `test-uplink` | ARP poisoning to impersonate the gateway | L2 |
| `test-downlink` | Cross-band downlink MAC spoofing | L1/L2 |

4. **Score** — Aggregate findings into a 0-10 risk score with severity levels
5. **Report** — Rich terminal output + JSON export

## The crypto chain

The core GTK extraction follows the IEEE 802.11i key hierarchy:

```
Passphrase + SSID
  |  PBKDF2-SHA1 (4096 iterations)
  v
PMK (256 bits)
  |  PRF-512(PMK, "Pairwise key expansion", min/max(MACs) || min/max(Nonces))
  v
PTK (512 bits) = KCK (128) + KEK (128) + TK (128) + ...
  |  AES Key Unwrap(KEK, Message3.KeyData)
  v
GTK (128 bits)
  |  AES-CCM(TK=GTK, nonce=Priority||BSSID||PN, AAD from 802.11 header)
  v
CCMP-encrypted broadcast frame → injected via AP → forwarded to all clients
```

## Real-world findings

Tested on a hotel network (MikroTik router, WPA2-PSK, shared password):

- **113 guest devices** visible via ARP — no client isolation at L2
- An unauthenticated **Prometheus + Grafana** stack found running on a guest device, leaking another guest's email, employer, Anthropic org IDs, Claude Code session history, and model usage
- Gateway running VRRP with captive portal on a flat /20 subnet (4094 hosts)

## Architecture

```
src/airsnitch/
  cli.py              Click CLI with command groups
  config.py           Constants, known vulnerable devices
  core/
    adapter.py         Monitor mode toggle, interface management
    context.py         Build NetworkContext from interface
    packets.py         PacketEngine (scapy wrapper with rate limiting)
    types.py           ClientInfo, APInfo, Finding, RiskScore, NetworkContext
  discovery/
    scanner.py         ARP sweep, passive sniff, gateway detection
    fingerprint.py     OUI lookup, HTTP/SNMP probing
  attacks/
    base.py            BaseAttackTest (preflight, execute, cleanup)
    gtk_injection.py   Full 802.11i key derivation + CCMP encryption
    gateway_bounce.py  L2/L3 redirect via gateway
    uplink_impersonation.py  ARP cache poisoning
    downlink_spoof.py  Cross-band MAC spoofing
  scoring/
    engine.py          Weighted risk aggregation
  reporting/
    terminal.py        Rich console output
    json_report.py     Machine-readable report
  safeguards/
    authorization.py   Auth codes, disclaimers, root check
    audit.py           JSONL audit log of all actions
    rate_limiter.py    Token bucket packet rate limiting
```

## Requirements

- **Linux** with a monitor-mode-capable Wi-Fi adapter (e.g., Alfa AWUS036ACH)
- Python 3.11+
- Root privileges

macOS can run discovery and L2/L3 tests but **cannot** do GTK extraction (no monitor mode / 802.11 injection).

## Install

```bash
git clone https://github.com/sderosiaux/hotel-airsnitch-scanner.git
cd hotel-airsnitch-scanner
uv sync
```

## Usage

```bash
# Generate auth code (required for injection tests)
uv run airsnitch gen-auth-code --hotel-name "Tivoli"

# Discovery only (safe, passive + ARP)
sudo uv run airsnitch -i wlan0 -s "HotelWiFi" -p "password" discover

# Fingerprint the AP
sudo uv run airsnitch -i wlan0 -s "HotelWiFi" -p "password" fingerprint

# Individual tests
sudo uv run airsnitch -i wlan0 -s "HotelWiFi" -p "password" -a AIRSNITCH-XXXXXXXX test-gtk
sudo uv run airsnitch -i wlan0 -s "HotelWiFi" -p "password" -a AIRSNITCH-XXXXXXXX test-gateway

# Full scan (all tests + risk score + report)
sudo uv run airsnitch -i wlan0 -s "HotelWiFi" -p "password" -a AIRSNITCH-XXXXXXXX -y full-scan

# Passive monitoring
sudo uv run airsnitch -i wlan0 monitor --duration 120
```

## Testing

```bash
# Unit + crypto tests (runs on macOS/Linux, no hardware needed)
uv run pytest                      # 110 tests

# Integration tests with virtual Wi-Fi (Linux VM via Vagrant)
vagrant up
vagrant ssh -c 'sudo /vagrant/tests/hwsim/setup_hwsim.sh'
vagrant ssh -c 'cd /vagrant && sudo pytest tests/hwsim/ -v'

# Full GTK extraction demo against virtual radios
vagrant ssh -c 'sudo /tmp/airsnitch-venv/bin/python /vagrant/tests/hwsim/run_gtk_extraction.py'
```

The test suite verifies the full crypto chain against IEEE 802.11i test vectors (H.4 PMK vector), RFC 3394 AES Key Wrap, and hostapd-derived EAPOL frames — no mocking.

## Safeguards

- Authorization codes required for injection tests
- Per-target confirmation prompts (override with `-y`)
- Rate-limited packet transmission (configurable `--pps`)
- Full JSONL audit log of every action
- Disclaimer and consent flow

## Disclaimer

This tool is for **authorized security testing only**. Only use it on networks you own or have explicit written permission to test. Unauthorized use may violate laws in your jurisdiction.

## References

- [AirSnitch: Exploiting Client Isolation in Hotel Wi-Fi (NDSS 2026)](https://www.ndss-symposium.org/ndss-paper/auto-draft-732/)
- IEEE 802.11i-2004 — Security mechanisms for wireless LANs
- RFC 3394 — AES Key Wrap Algorithm

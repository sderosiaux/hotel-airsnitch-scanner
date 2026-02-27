# Hotel AirSnitch Scanner

Wi-Fi security assessment tool targeting AirSnitch client isolation bypass (NDSS 2026).

## Stack
- Python 3.11+, scapy, click, rich, netifaces, cryptography
- Entry point: `src/airsnitch/cli.py`
- Tests: `tests/`

## Architecture
- `core/` - Adapter, packet engine, types, context
- `discovery/` - Network scanning, router fingerprinting
- `attacks/` - Test modules (GTK injection, gateway bounce, downlink spoof, uplink impersonation)
- `scoring/` - Risk scoring engine
- `reporting/` - Terminal + JSON output
- `safeguards/` - Authorization, audit logging, rate limiting

## Commands
```
uv sync
uv run airsnitch --help
uv run pytest
```

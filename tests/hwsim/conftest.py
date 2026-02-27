"""Fixtures for mac80211_hwsim integration tests.

Requires Linux with mac80211_hwsim loaded and setup_hwsim.sh already run.
All tests in this directory are marked with @pytest.mark.hwsim.
"""

from __future__ import annotations

from pathlib import Path

import pytest

HWSIM_ENV_FILE = Path("/tmp/airsnitch_hwsim_env")
HWSIM_MODULE_PATH = Path("/sys/module/mac80211_hwsim")


def _load_hwsim_env() -> dict[str, str]:
    """Parse /tmp/airsnitch_hwsim_env into a dict."""
    if not HWSIM_ENV_FILE.exists():
        return {}
    env = {}
    for line in HWSIM_ENV_FILE.read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k] = v
    return env


def pytest_collection_modifyitems(items):
    """Auto-mark all tests in tests/hwsim/ with the hwsim marker."""
    for item in items:
        if "hwsim" in str(item.fspath):
            item.add_marker(pytest.mark.hwsim)


def pytest_configure(config):
    config.addinivalue_line("markers", "hwsim: requires mac80211_hwsim (Linux only)")


@pytest.fixture(scope="session")
def hwsim_available() -> bool:
    """Check if mac80211_hwsim is loaded."""
    return HWSIM_MODULE_PATH.exists()


@pytest.fixture(scope="session")
def hwsim_env(hwsim_available) -> dict[str, str]:
    """Load hwsim environment. Skip all tests if not available."""
    if not hwsim_available:
        pytest.skip("mac80211_hwsim not loaded — run setup_hwsim.sh as root first")
    env = _load_hwsim_env()
    if not env:
        pytest.skip(f"{HWSIM_ENV_FILE} not found — run setup_hwsim.sh first")
    required = {"AP_IFACE", "VICTIM_IFACE", "ATTACK_IFACE", "SSID", "PASSWORD"}
    missing = required - env.keys()
    if missing:
        pytest.skip(f"Missing hwsim env vars: {missing}")
    return env


@pytest.fixture(scope="session")
def ap_iface(hwsim_env) -> str:
    return hwsim_env["AP_IFACE"]


@pytest.fixture(scope="session")
def victim_iface(hwsim_env) -> str:
    return hwsim_env["VICTIM_IFACE"]


@pytest.fixture(scope="session")
def attacker_iface(hwsim_env) -> str:
    return hwsim_env["ATTACK_IFACE"]


@pytest.fixture(scope="session")
def ap_ip(hwsim_env) -> str:
    return hwsim_env.get("AP_IP", "192.168.50.1")


@pytest.fixture(scope="session")
def victim_ip(hwsim_env) -> str:
    return hwsim_env.get("VICTIM_IP", "192.168.50.10")


@pytest.fixture(scope="session")
def ssid(hwsim_env) -> str:
    return hwsim_env["SSID"]


@pytest.fixture(scope="session")
def password(hwsim_env) -> str:
    return hwsim_env["PASSWORD"]

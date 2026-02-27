#!/bin/bash
# Teardown mac80211_hwsim virtual Wi-Fi environment.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root" >&2
    exit 1
fi

echo "Stopping services..."

# Kill hostapd
if [[ -f /tmp/airsnitch_hostapd.pid ]]; then
    kill "$(cat /tmp/airsnitch_hostapd.pid)" 2>/dev/null || true
    rm -f /tmp/airsnitch_hostapd.pid
fi
pkill -f "hostapd.*airsnitch" 2>/dev/null || true

# Kill wpa_supplicant
if [[ -f /tmp/airsnitch_wpa_supplicant.pid ]]; then
    kill "$(cat /tmp/airsnitch_wpa_supplicant.pid)" 2>/dev/null || true
    rm -f /tmp/airsnitch_wpa_supplicant.pid
fi
pkill -f "wpa_supplicant.*airsnitch" 2>/dev/null || true

# Kill any lingering dhclient
pkill -f "dhclient.*wlan" 2>/dev/null || true

# Remove kernel module
if lsmod | grep -q mac80211_hwsim; then
    rmmod mac80211_hwsim
    echo "mac80211_hwsim unloaded."
else
    echo "mac80211_hwsim not loaded."
fi

# Cleanup temp files
rm -f /tmp/airsnitch_hostapd.conf
rm -f /tmp/airsnitch_wpa_supplicant.conf
rm -f /tmp/airsnitch_hwsim_env

echo "Teardown complete."

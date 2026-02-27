#!/bin/bash
# Setup mac80211_hwsim virtual Wi-Fi radios for integration testing.
# Requires: root, Linux with mac80211_hwsim kernel module.
set -euo pipefail

cleanup() {
    echo "Cleaning up on error..."
    pkill -f "hostapd.*AirSnitchTest" 2>/dev/null || true
    pkill -f "wpa_supplicant" 2>/dev/null || true
    rmmod mac80211_hwsim 2>/dev/null || true
}
trap cleanup ERR

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root" >&2
    exit 1
fi

# Unload first if leftover
rmmod mac80211_hwsim 2>/dev/null || true
sleep 1

# Load 3 virtual radios: AP, victim client, attacker
modprobe mac80211_hwsim radios=3
sleep 1

# Identify interfaces by listing all wlan devices (hwsim creates wlan0, wlan1, wlan2)
# Sort by interface index to get deterministic ordering
mapfile -t IFACES < <(iw dev | grep 'Interface' | awk '{print $2}' | sort)

if [[ ${#IFACES[@]} -lt 3 ]]; then
    echo "ERROR: Expected 3 hwsim interfaces, got ${#IFACES[@]}" >&2
    iw dev >&2
    exit 1
fi

AP_IFACE="${IFACES[0]}"
VICTIM_IFACE="${IFACES[1]}"
ATTACK_IFACE="${IFACES[2]}"

echo "Interfaces: AP=$AP_IFACE VICTIM=$VICTIM_IFACE ATTACKER=$ATTACK_IFACE"

# Bring all interfaces up
ip link set "$AP_IFACE" up
ip link set "$VICTIM_IFACE" up
ip link set "$ATTACK_IFACE" up

# Start hostapd (WPA2-PSK AP)
cat > /tmp/airsnitch_hostapd.conf <<CONF
interface=$AP_IFACE
driver=nl80211
hw_mode=g
channel=1
ssid=AirSnitchTest
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase=TestPassword123
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
CONF
hostapd -B /tmp/airsnitch_hostapd.conf -P /tmp/airsnitch_hostapd.pid
sleep 2

# Assign AP a static IP
ip addr add 192.168.50.1/24 dev "$AP_IFACE" 2>/dev/null || true

# Connect victim client
cat > /tmp/airsnitch_wpa_victim.conf <<CONF
ctrl_interface=/var/run/wpa_victim
network={
    ssid="AirSnitchTest"
    psk="TestPassword123"
}
CONF
wpa_supplicant -B -Dnl80211 -i"$VICTIM_IFACE" -c/tmp/airsnitch_wpa_victim.conf \
    -P /tmp/airsnitch_wpa_victim.pid
sleep 3

# Assign victim a static IP
ip addr add 192.168.50.10/24 dev "$VICTIM_IFACE" 2>/dev/null || true

# Export for test consumption
cat > /tmp/airsnitch_hwsim_env <<ENVFILE
AP_IFACE=$AP_IFACE
VICTIM_IFACE=$VICTIM_IFACE
ATTACK_IFACE=$ATTACK_IFACE
AP_IP=192.168.50.1
VICTIM_IP=192.168.50.10
SSID=AirSnitchTest
PASSWORD=TestPassword123
AP_MAC=$(ip link show "$AP_IFACE" | awk '/link\/ether/{print $2}')
VICTIM_MAC=$(ip link show "$VICTIM_IFACE" | awk '/link\/ether/{print $2}')
ATTACKER_MAC=$(ip link show "$ATTACK_IFACE" | awk '/link\/ether/{print $2}')
ENVFILE

echo "Setup complete."
echo "AP=$AP_IFACE (192.168.50.1)"
echo "VICTIM=$VICTIM_IFACE (192.168.50.10)"
echo "ATTACKER=$ATTACK_IFACE"
echo "Environment written to /tmp/airsnitch_hwsim_env"

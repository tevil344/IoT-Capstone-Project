#!/usr/bin/env bash
# ==============================================================================
# Raspberry Pi Zero-Trust Gateway - Network Interface & VLAN Provisioning
# Target: Raspberry Pi 4 / 5 (Raspberry Pi OS / Debian Bookworm)
# ==============================================================================
set -euo pipefail

GATEWAY_VLAN_TRUNK_IF="eth0"
TRUSTED_VLAN_ID=10
QUARANTINE_VLAN_ID=20
CAPTURE_IF="mon0"

echo "[*] Initializing Network Interfaces and 802.1Q VLAN sub-interfaces..."

# Ensure 8021q kernel module is loaded
if ! lsmod | grep -q 8021q; then
    echo "[+] Loading 8021q kernel module..."
    modprobe 8021q
fi

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.forwarding=1

# Configure VLAN Trunk base interface
ip link set dev "${GATEWAY_VLAN_TRUNK_IF}" up promisc on

# Create VLAN 10 (Trusted Zone) sub-interface
if ! ip link show "${GATEWAY_VLAN_TRUNK_IF}.${TRUSTED_VLAN_ID}" >/dev/null 2>&1; then
    echo "[+] Creating VLAN ${TRUSTED_VLAN_ID} interface (${GATEWAY_VLAN_TRUNK_IF}.${TRUSTED_VLAN_ID})..."
    ip link add link "${GATEWAY_VLAN_TRUNK_IF}" name "${GATEWAY_VLAN_TRUNK_IF}.${TRUSTED_VLAN_ID}" type vlan id ${TRUSTED_VLAN_ID}
fi
ip addr add 192.168.10.2/24 dev "${GATEWAY_VLAN_TRUNK_IF}.${TRUSTED_VLAN_ID}" 2>/dev/null || true
ip link set dev "${GATEWAY_VLAN_TRUNK_IF}.${TRUSTED_VLAN_ID}" up

# Create VLAN 20 (Quarantine Zone) sub-interface
if ! ip link show "${GATEWAY_VLAN_TRUNK_IF}.${QUARANTINE_VLAN_ID}" >/dev/null 2>&1; then
    echo "[+] Creating VLAN ${QUARANTINE_VLAN_ID} interface (${GATEWAY_VLAN_TRUNK_IF}.${QUARANTINE_VLAN_ID})..."
    ip link add link "${GATEWAY_VLAN_TRUNK_IF}" name "${GATEWAY_VLAN_TRUNK_IF}.${QUARANTINE_VLAN_ID}" type vlan id ${QUARANTINE_VLAN_ID}
fi
ip addr add 192.168.20.2/24 dev "${GATEWAY_VLAN_TRUNK_IF}.${QUARANTINE_VLAN_ID}" 2>/dev/null || true
ip link set dev "${GATEWAY_VLAN_TRUNK_IF}.${QUARANTINE_VLAN_ID}" up

echo "[✔] VLAN Sub-interfaces active:"
ip -br addr show | grep -E "${GATEWAY_VLAN_TRUNK_IF}\."

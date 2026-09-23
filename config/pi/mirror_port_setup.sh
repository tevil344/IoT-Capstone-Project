#!/usr/bin/env bash
# ==============================================================================
# Raspberry Pi Zero-Trust Gateway - SPAN / Mirror Port & Inline Mirroring Setup
# ==============================================================================
set -euo pipefail

# Choose topology:
# 1) INLINE: Bridge between eth0 (LAN/Quarantine) and eth1 (Switch), mirrored to dummy0/tap0
# 2) SPAN: Dedicated mirror port from managed switch arriving on eth1
MODE="${1:-span}" # "span" or "inline"
SOURCE_IF="${2:-eth0}"
MIRROR_IF="${3:-mon0}"

echo "[*] Setting up traffic mirroring in [${MODE}] mode..."

if [ "$MODE" = "span" ]; then
    echo "[+] Configuring SPAN/Mirror port on ${SOURCE_IF}..."
    ip link set dev "${SOURCE_IF}" up promisc on
    # Disable hardware checksum/offloads to prevent truncation of mirrored frames
    ethtool -K "${SOURCE_IF}" rx off tx off gso off tso off gro off 2>/dev/null || true
    echo "[✔] SPAN capture interface ${SOURCE_IF} configured in promiscuous mode."

elif [ "$MODE" = "inline" ]; then
    echo "[+] Configuring Linux Traffic Control (tc) ingress/egress mirroring..."
    # Create dummy interface to receive mirrored traffic if needed
    if ! ip link show "${MIRROR_IF}" >/dev/null 2>&1; then
        echo "[+] Creating virtual mirror device ${MIRROR_IF}..."
        ip link add dev "${MIRROR_IF}" type dummy
    fi
    ip link set dev "${MIRROR_IF}" up promisc on

    # Clear existing ingress qdiscs on source
    tc qdisc del dev "${SOURCE_IF}" ingress 2>/dev/null || true
    tc qdisc add dev "${SOURCE_IF}" ingress

    # Mirror all ingress traffic to MIRROR_IF
    tc filter add dev "${SOURCE_IF}" parent ffff: protocol all u32 \
        match u32 0 0 \
        action mirred egress mirror dev "${MIRROR_IF}"

    # Set up root egress qdisc and mirror egress traffic
    tc qdisc del dev "${SOURCE_IF}" root 2>/dev/null || true
    tc qdisc add dev "${SOURCE_IF}" handle 1: root prio
    tc filter add dev "${SOURCE_IF}" parent 1: protocol all u32 \
        match u32 0 0 \
        action mirred egress mirror dev "${MIRROR_IF}"

    echo "[✔] Bidirectional traffic on ${SOURCE_IF} is mirrored to ${MIRROR_IF}."
else
    echo "[-] Unknown mode: ${MODE}. Usage: $0 [span|inline] [source_if] [mirror_if]"
    exit 1
fi


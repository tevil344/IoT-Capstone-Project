#!/usr/bin/env bash
# ==============================================================================
# Raspberry Pi 4/5 Zero-Trust Gateway - Automated Production Provisioning Script
# Target OS: Raspberry Pi OS (Debian Bookworm 64-bit) / Debian 12
# ==============================================================================
set -euo pipefail

INSTALL_DIR="/opt/iot-gateway"
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "======================================================================"
echo " Provisioning Raspberry Pi Zero-Trust IoT Gateway"
echo "======================================================================"

# 1. Require Root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (use sudo)."
    exit 1
fi

# 2. Install System Dependencies
echo "[+] Installing system packages (nftables, tcpdump, python3-venv, ethtool)..."
apt-get update -qq
apt-get install -y -qq \
    nftables \
    tcpdump \
    ethtool \
    python3 \
    python3-venv \
    python3-pip \
    libcap2-bin \
    sqlite3

# 3. Kernel Modules and Networking
echo "[+] Enabling 802.1Q VLAN support and IP Forwarding..."
modprobe 8021q || true
echo "8021q" >> /etc/modules-load.d/8021q.conf || true

sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-iot-zerotrust.conf
sysctl --system >/dev/null

# 4. Deploy Application Files
echo "[+] Deploying gateway files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp -r "${CURRENT_DIR}/gateway" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/config" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/inventory" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/scripts" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/models" "${INSTALL_DIR}/" 2>/dev/null || true
cp "${CURRENT_DIR}/requirements.txt" "${INSTALL_DIR}/"

mkdir -p "${INSTALL_DIR}/data"
mkdir -p "${INSTALL_DIR}/models"

# 5. Create Virtual Environment and Install Python Dependencies
echo "[+] Setting up Python virtual environment in ${INSTALL_DIR}/.venv..."
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip -q
"${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q

# 6. Initialize Machine Learning Artifacts
if [ ! -f "${INSTALL_DIR}/models/baseline_rf.joblib" ]; then
    echo "[+] Initializing baseline ML classifier and open-set models..."
    "${INSTALL_DIR}/.venv/bin/python" -m gateway.models.train --output "${INSTALL_DIR}/models/baseline_rf.joblib"
fi

# 7. Install Systemd Daemons
echo "[+] Installing systemd services..."
cp "${CURRENT_DIR}/deploy/systemd/"*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable iot-gateway.service
systemctl enable iot-dashboard.service

echo "======================================================================"
echo " [✔] Provisioning Complete!"
echo " Start Gateway:   systemctl start iot-gateway.service"
echo " Start Dashboard: systemctl start iot-dashboard.service"
echo " Web Dashboard:   http://$(hostname -I | awk '{print $1}'):8080"
echo "======================================================================"


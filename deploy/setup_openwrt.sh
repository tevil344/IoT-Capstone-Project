#!/bin/sh
# ==============================================================================
# OpenWrt Access Point / Router Zero-Trust Provisioning Script
# Target: OpenWrt 22.03+ / 23.05+ (nftables firewall4, dnsmasq, hostapd)
# ==============================================================================
set -e

CONFIG_SRC="/tmp/iot_configs"
BACKUP_DIR="/etc/config/backup_$(date +%Y%m%d_%H%M%S)"

echo "======================================================================"
echo " Provisioning OpenWrt Zero-Trust VLANs & nftables Ruleset"
echo "======================================================================"

mkdir -p "$BACKUP_DIR"
echo "[+] Backing up existing UCI configurations to $BACKUP_DIR..."
cp /etc/config/network "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/config/wireless "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/config/dhcp "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/config/firewall "$BACKUP_DIR/" 2>/dev/null || true

# Apply UCI configs if provided
if [ -d "$CONFIG_SRC" ]; then
    echo "[+] Applying Zero-Trust OpenWrt UCI configurations..."
    [ -f "$CONFIG_SRC/network" ] && cp "$CONFIG_SRC/network" /etc/config/network
    [ -f "$CONFIG_SRC/wireless" ] && cp "$CONFIG_SRC/wireless" /etc/config/wireless
    [ -f "$CONFIG_SRC/dhcp" ] && cp "$CONFIG_SRC/dhcp" /etc/config/dhcp
    [ -f "$CONFIG_SRC/firewall" ] && cp "$CONFIG_SRC/firewall" /etc/config/firewall

    # Install custom nftables ruleset
    if [ -f "$CONFIG_SRC/gateway.nft" ]; then
        echo "[+] Installing gateway nftables ruleset..."
        mkdir -p /etc/nftables.d
        cp "$CONFIG_SRC/gateway.nft" /etc/nftables.d/gateway.nft
    fi
fi

# Reload OpenWrt Services
echo "[+] Reloading network and firewall subsystems..."
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
/etc/init.d/firewall restart

echo "======================================================================"
echo " [✔] OpenWrt Zero-Trust Provisioning Complete!"
echo " VLAN 10 (Trusted):     192.168.10.1/24 (SSID: IoT-Secure-Production)"
echo " VLAN 20 (Quarantine):  192.168.20.1/24 (SSID: IoT-Onboarding [Isolated])"
echo "======================================================================"

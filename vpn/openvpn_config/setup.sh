#!/usr/bin/env bash
# =============================================================================
# setup.sh — PKI and OpenVPN server initialisation for the legacy VPN baseline
# Run once on the gateway VM inside the GNS3 lab environment.
# =============================================================================

set -euo pipefail

EASY_RSA_DIR="/etc/openvpn/easy-rsa"
PKI_DIR="/etc/openvpn/pki"
LOG_DIR="/var/log/openvpn"

echo "=== Installing OpenVPN and easy-rsa ==="
apt-get update -qq
apt-get install -y openvpn easy-rsa

echo "=== Initialising PKI ==="
make-cadir "$EASY_RSA_DIR"
cd "$EASY_RSA_DIR"

./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa --batch gen-req server nopass
./easyrsa --batch sign-req server server
./easyrsa gen-dh
openvpn --genkey --secret pki/ta.key

echo "=== Copying PKI files ==="
mkdir -p "$PKI_DIR"
cp pki/ca.crt              "$PKI_DIR/"
cp pki/issued/server.crt   "$PKI_DIR/"
cp pki/private/server.key  "$PKI_DIR/"
cp pki/dh.pem              "$PKI_DIR/"
cp pki/ta.key              "$PKI_DIR/"

echo "=== Creating log directory ==="
mkdir -p "$LOG_DIR"

echo "=== Enabling IP forwarding ==="
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf

echo "=== Starting OpenVPN ==="
systemctl enable openvpn@server
systemctl start  openvpn@server

echo ""
echo "Legacy VPN server is running."
echo "Status: systemctl status openvpn@server"
echo "Logs  : tail -f $LOG_DIR/server.log"
echo ""
echo "NOTE: This is an intentionally basic setup for research comparison."
echo "      No ZTA controls, no ML detection, no micro-segmentation."

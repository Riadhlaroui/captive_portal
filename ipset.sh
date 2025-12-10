#!/bin/bash

# Configuration
# --------------------
HOTSPOT_IF="wlan1"       # The interface users connect to
INTERNET_IF="wlan0"      # The interface providing internet (WAN)
PORTAL_IP="192.168.10.1" # The gateway IP
PORTAL_PORT="8080"       # The port your Go app runs on
IPSET_NAME="allowed_users"

# Function to clean up when exiting
cleanup() {
    echo "Stopping hotspot and captive portal..."
    sudo pkill dnsmasq
    sudo pkill hostapd
    sudo pkill -f "go run main.go"

    # Flush iptables
    sudo iptables -t nat -F
    sudo iptables -F
    sudo iptables -X  # Delete custom chains

    # Destroy the IP set
    sudo ipset destroy $IPSET_NAME

    # Disable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=0

    # Reset wlan1
    sudo ip addr flush dev $HOTSPOT_IF
    sudo ip link set $HOTSPOT_IF down

    echo "Cleanup complete."
    exit 0
}

# Trap SIGINT (Ctrl+C) and call cleanup
trap cleanup SIGINT

# Kill conflicting services just in case
sudo pkill dnsmasq
sudo pkill hostapd

# Enable IP Forwarding
echo "Enabling IP Forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# Configure wlan1 for AP
echo "Configuring Interface $HOTSPOT_IF..."
sudo ip link set $HOTSPOT_IF down
sudo ip addr flush dev $HOTSPOT_IF
sudo ip addr add $PORTAL_IP/24 dev $HOTSPOT_IF
sudo ip link set $HOTSPOT_IF up

# Start dnsmasq in background
echo "Starting DNSMasq..."
sudo dnsmasq --conf-file=/etc/dnsmasq-test.conf --no-daemon &
DNSMASQ_PID=$!

# ----------------------------------------------------------------
# IPSET SETUP (The Magic Part)
# ----------------------------------------------------------------
echo "Initializing IPSet..."
# Create the set if it doesn't exist
sudo ipset create $IPSET_NAME hash:ip -exist
# Clear it to ensure no stale users from last session
sudo ipset flush $IPSET_NAME

# ----------------------------------------------------------------
# IPTABLES RULES
# ----------------------------------------------------------------
echo "Applying Firewall Rules..."

# Flush old rules
sudo iptables -t nat -F
sudo iptables -F

# 1. ALLOW INTERNET FOR AUTHORIZED USERS
# If IP is in the set, skip all portal redirects (ACCEPT in PREROUTING)
sudo iptables -t nat -A PREROUTING -i $HOTSPOT_IF -m set --match-set $IPSET_NAME src -j ACCEPT

# If IP is in the set, allow FORWARDING to internet
sudo iptables -A FORWARD -i $HOTSPOT_IF -o $INTERNET_IF -m set --match-set $IPSET_NAME src -j ACCEPT

# Allow established connections (replies from internet)
sudo iptables -A FORWARD -i $INTERNET_IF -o $HOTSPOT_IF -m state --state RELATED,ESTABLISHED -j ACCEPT

# Enable NAT (Masquerade) for outgoing traffic
sudo iptables -t nat -A POSTROUTING -o $INTERNET_IF -j MASQUERADE

# 2. CAPTIVE PORTAL REDIRECTION (For everyone else)
# Create chain
sudo iptables -t nat -N CAPTIVE_PORTAL 2>/dev/null

# Send HTTP (80) traffic to the Go Portal
sudo iptables -t nat -A PREROUTING -i $HOTSPOT_IF -p tcp --dport 80 -j CAPTIVE_PORTAL
sudo iptables -t nat -A CAPTIVE_PORTAL -p tcp --dport 80 -j DNAT --to-destination $PORTAL_IP:$PORTAL_PORT

# Redirect DNS queries to local dnsmasq (Important for "fake" domains)
sudo iptables -t nat -A PREROUTING -i $HOTSPOT_IF -p udp --dport 53 -j DNAT --to-destination $PORTAL_IP

# Block HTTPS (443) for unauthorized users
# We REJECT instead of DROP so the browser fails fast and tries HTTP/Gen204 check
sudo iptables -A FORWARD -i $HOTSPOT_IF -p tcp --dport 443 -j REJECT --reject-with tcp-reset

# ----------------------------------------------------------------
# START SERVICES
# ----------------------------------------------------------------

# Start access point
echo "Starting Hostapd..."
sudo hostapd /etc/hostapd/hostapd.conf &
HOSTAPD_PID=$!

# Start Go captive portal (run as root!)
echo "Starting Go Portal..."
cd /home/riadh/Desktop/projects/captive-portal
sudo go run main.go &
GO_PID=$!

echo "✅ Captive Portal is Running."
echo "   Gateway: $PORTAL_IP"
echo "   Portal URL: http://$PORTAL_IP:$PORTAL_PORT"

# Wait for all background processes
wait $DNSMASQ_PID $HOSTAPD_PID $GO_PID
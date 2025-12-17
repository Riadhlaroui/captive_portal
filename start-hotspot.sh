#!/bin/bash

# Old version of start-hotspot.sh without IPSet
# Function to clean up when exiting
cleanup() {
    echo "Stopping hotspot and captive portal..."
    sudo pkill dnsmasq
    sudo pkill hostapd
    sudo pkill -f "go run main.go"

    # Flush iptables rules we added
    sudo iptables -t nat -F
    sudo iptables -F

    # Disable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=0

    # Reset wlan1
    sudo ip addr flush dev wlan1
    sudo ip link set wlan1 down

    exit 0
}

# Trap SIGINT (Ctrl+C) and call cleanup
trap cleanup SIGINT

# Kill conflicting services just in case
sudo pkill dnsmasq
sudo pkill hostapd

# Enable IP Forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Configure wlan1 for AP
sudo ip link set wlan1 down
sudo ip addr flush dev wlan1
sudo ip addr add 192.168.10.1/24 dev wlan1
sudo ip link set wlan1 up

# Start dnsmasq in background
sudo dnsmasq --conf-file=/etc/dnsmasq-test.conf --no-daemon &
DNSMASQ_PID=$!

# Flush old iptables rules
sudo iptables -t nat -F
sudo iptables -F

# Create captive portal chain if it doesn't exist
sudo iptables -t nat -N CAPTIVE_PORTAL 2>/dev/null

# Redirect all HTTP traffic from wlan1 to CAPTIVE_PORTAL
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j CAPTIVE_PORTAL

# In CAPTIVE_PORTAL chain, redirect all HTTP to portal
sudo iptables -t nat -A CAPTIVE_PORTAL -p tcp --dport 80 -j DNAT --to-destination 192.168.10.1:8080

# Redirect all DNS queries to local dnsmasq
sudo iptables -t nat -A PREROUTING -i wlan1 -p udp --dport 53 -j DNAT --to-destination 192.168.10.1

# Block HTTPS until authorized
sudo iptables -I FORWARD -i wlan1 -p tcp --dport 443 -j REJECT

# NAT Routing for wlan0 (internet interface)
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan1 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Start access point
sudo hostapd /etc/hostapd/hostapd.conf &
HOSTAPD_PID=$!

# Start Go captive portal (run as root!)
cd /home/riadh/Desktop/projects/captive-portal
sudo go run main.go &
GO_PID=$!

# Wait for all background processes
wait $DNSMASQ_PID $HOSTAPD_PID $GO_PID

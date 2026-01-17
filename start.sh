#!/usr/bin/env bash
set -euo pipefail

# Determine the interface Pi-hole should bind to.
# MikroTik RouterOS containers typically expose the NIC as veth1.
detect_iface() {
  if ip link show veth1 >/dev/null 2>&1; then
    echo "veth1"
    return
  fi

  # Fallback: first UP interface that isn't loopback; strip "@ifXX" suffix
  ip -o link show up \
    | awk -F': ' '$2!="lo"{print $2; exit}' \
    | cut -d'@' -f1
}

IFACE="${PIHOLE_INTERFACE:-$(detect_iface)}"

# Persist the interface into Pi-hole configs (prevents "unknown interface eth0")
if [[ -f /etc/pihole/setupVars.conf ]]; then
  if grep -q '^PIHOLE_INTERFACE=' /etc/pihole/setupVars.conf; then
    sed -i "s/^PIHOLE_INTERFACE=.*/PIHOLE_INTERFACE=${IFACE}/" /etc/pihole/setupVars.conf
  else
    echo "PIHOLE_INTERFACE=${IFACE}" >> /etc/pihole/setupVars.conf
  fi
fi

if [[ -f /etc/dnsmasq.d/01-pihole.conf ]]; then
  # Only replace if an interface line exists; otherwise append one.
  if grep -q '^interface=' /etc/dnsmasq.d/01-pihole.conf; then
    sed -i "s/^interface=.*/interface=${IFACE}/" /etc/dnsmasq.d/01-pihole.conf
  else
    echo "interface=${IFACE}" >> /etc/dnsmasq.d/01-pihole.conf
  fi
fi

# Restart FTL so it picks up the interface change
sudo service pihole-FTL restart > /dev/null 2>&1 || true

# Start other services (idempotent-ish)
sudo service lighttpd start > /dev/null 2>&1 || true
sudo service ssh start > /dev/null 2>&1 || true

sleep infinity

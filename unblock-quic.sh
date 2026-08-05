#!/bin/bash
#
# Reverse block-quic.sh — restore /etc/pf.conf and remove the QUIC block.
# Run:  sudo ./unblock-quic.sh
set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

if [ -f /etc/pf.conf.familywebfilter.bak ]; then
  mv /etc/pf.conf.familywebfilter.bak /etc/pf.conf
else
  # strip our two lines if the backup is gone
  grep -v "com.familywebfilter" /etc/pf.conf > /etc/pf.conf.tmp && mv /etc/pf.conf.tmp /etc/pf.conf
fi
rm -f /etc/pf.anchors/com.familywebfilter
pfctl -f /etc/pf.conf 2>/dev/null || true
echo "QUIC block removed."

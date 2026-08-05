#!/bin/bash
#
# Block QUIC / HTTP-3 (UDP 443) so browsers fall back to TCP through the proxy.
# Without this, Chrome uses HTTP-3 for Google/YouTube and bypasses the proxy entirely.
# Run:  sudo ./block-quic.sh    Reverse with ./unblock-quic.sh.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

ANCHOR=/etc/pf.anchors/com.familywebfilter
# "block return" (not "drop") so the browser fails over to TCP immediately instead of
# waiting for a UDP timeout.
printf 'block return out proto udp from any to any port 443\n' > "$ANCHOR"

# Reference + load our anchor from /etc/pf.conf (idempotent; back up first).
if ! grep -q "com.familywebfilter" /etc/pf.conf; then
  cp /etc/pf.conf /etc/pf.conf.familywebfilter.bak
  printf '\nanchor "com.familywebfilter"\nload anchor "com.familywebfilter" from "%s"\n' "$ANCHOR" >> /etc/pf.conf
fi

# Load the ruleset (do NOT hide errors) and enable pf.
pfctl -f /etc/pf.conf
pfctl -E 2>/dev/null || pfctl -e 2>/dev/null || true

# Verify the rule actually landed in the anchor.
if pfctl -a com.familywebfilter -sr 2>/dev/null | grep -q "443"; then
  echo "OK — QUIC (UDP 443) is blocked."
  echo "Now FULLY QUIT your browser (Cmd-Q) and reopen it — Chrome caches HTTP-3."
else
  echo "FAILED — rule did not load. Run 'sudo pfctl -f /etc/pf.conf' and read the error." >&2
  exit 1
fi

#!/bin/bash
#
# Regenerate the mitmproxy CA with a fresh (valid) serial and re-trust it — fixes the
# "non-positive serial number" deprecation before a future `cryptography` upgrade turns
# it into a hard crash. Run:  sudo ./regenerate-ca.sh
#
# After running, fully quit and reopen your browsers (they cached the old CA).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/venv"
CONFDIR="$DIR/mitm-ca"
CA="$CONFDIR/mitmproxy-ca-cert.pem"
PROXY_PLIST=/Library/LaunchDaemons/com.familywebfilter.proxy.plist
WATCHDOG_PLIST=/Library/LaunchDaemons/com.familywebfilter.watchdog.plist

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

echo "Pausing watchdog + proxy..."
launchctl bootout system/com.familywebfilter.watchdog 2>/dev/null || true
launchctl bootout system/com.familywebfilter.proxy 2>/dev/null || true
sleep 1

echo "Removing old CA trust + files..."
security delete-certificate -c mitmproxy /Library/Keychains/System.keychain 2>/dev/null || true
[ -d "$CONFDIR" ] && mv "$CONFDIR" "$CONFDIR.old.$(date +%s)"
mkdir -p "$CONFDIR"

echo "Generating a fresh CA..."
"$VENV/bin/mitmdump" --set confdir="$CONFDIR" -q >/dev/null 2>&1 &
MPID=$!
for _ in $(seq 1 40); do [ -f "$CA" ] && break; sleep 0.5; done
kill "$MPID" 2>/dev/null || true
[ -f "$CA" ] || { echo "CA generation failed" >&2; exit 1; }

echo "Trusting the new CA..."
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA"

echo "Restarting proxy + watchdog..."
launchctl bootstrap system "$PROXY_PLIST" 2>/dev/null || launchctl load -w "$PROXY_PLIST" 2>/dev/null || true
launchctl bootstrap system "$WATCHDOG_PLIST" 2>/dev/null || launchctl load -w "$WATCHDOG_PLIST" 2>/dev/null || true

echo "Done. Fully quit and reopen your browsers (they cached the old CA)."

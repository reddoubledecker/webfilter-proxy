#!/bin/bash
#
# Remove Family Web Filter (proxy). Run:  sudo ./uninstall.sh
# Leaves the venv, config/ and CA files on disk — delete the folder to remove fully.
set -uo pipefail

PROXY_PLIST=/Library/LaunchDaemons/com.familywebfilter.proxy.plist
UI_PLIST=/Library/LaunchDaemons/com.familywebfilter.ui.plist
WATCHDOG_PLIST=/Library/LaunchDaemons/com.familywebfilter.watchdog.plist

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

echo "Stopping LaunchDaemons..."
# Watchdog first, so it can't re-enable the proxy after we unset it below.
for pl in "$WATCHDOG_PLIST" "$PROXY_PLIST" "$UI_PLIST"; do
  launchctl unload -w "$pl" 2>/dev/null || true
  rm -f "$pl"
done
rm -f /usr/local/webfilter-proxy/config/watchdog.failopen /usr/local/webfilter-proxy/config/watchdog.fails /usr/local/webfilter-proxy/config/watchdog.wedged 2>/dev/null || true

echo "Unsetting system proxy..."
while IFS= read -r svc; do
  case "$svc" in ""|An\ asterisk*|\(*) continue;; esac
  networksetup -setwebproxystate "$svc" off 2>/dev/null || true
  networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

echo "Removing CA trust..."
security delete-certificate -c mitmproxy /Library/Keychains/System.keychain 2>/dev/null || true

echo "Done."
echo "  - Remove the 'Disable Chrome QUIC' profile in System Settings > General >"
echo "    Device Management, if you want QUIC re-enabled."
echo "  - If you ran block-quic.sh, run ./unblock-quic.sh to restore QUIC."

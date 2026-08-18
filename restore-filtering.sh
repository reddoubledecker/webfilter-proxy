#!/bin/bash
#
# Undo emergency-off.sh: re-point the system proxy at the filter, clear the emergency /
# fail-open state, and bring the watchdog + proxy back. Run:  sudo ./restore-filtering.sh
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
HOST=127.0.0.1
PORT=8080
MARKER="$DIR/config/emergency"
WATCHDOG_PLIST=/Library/LaunchDaemons/com.familywebfilter.watchdog.plist
WATCHDOG_LABEL=system/com.familywebfilter.watchdog

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

echo "Re-enabling the system proxy on all network services..."
while IFS= read -r svc; do
  case "$svc" in ""|\**|\(*) continue;; esac
  networksetup -setwebproxy "$svc" "$HOST" "$PORT" 2>/dev/null || true
  networksetup -setsecurewebproxy "$svc" "$HOST" "$PORT" 2>/dev/null || true
  networksetup -setproxybypassdomains "$svc" 127.0.0.1 localhost "*.local" 2>/dev/null || true
done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

echo "Clearing emergency + fail-open state..."
rm -f "$MARKER" "$DIR/config/watchdog.failopen" 2>/dev/null || true
echo 0 > "$DIR/config/watchdog.fails" 2>/dev/null || true

echo "Restarting the proxy + watchdog..."
launchctl kickstart -k system/com.familywebfilter.proxy 2>/dev/null || true
launchctl bootstrap system "$WATCHDOG_PLIST" 2>/dev/null \
  || launchctl kickstart -k "$WATCHDOG_LABEL" 2>/dev/null || true

echo ""
echo "Done — filtering restored. Verify with:  sudo $DIR/doctor.sh"

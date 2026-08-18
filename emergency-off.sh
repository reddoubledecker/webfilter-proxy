#!/bin/bash
#
# EMERGENCY BYPASS — restore unfiltered internet immediately when the filter is broken
# and you can't fix it right now. Stops the watchdog (so it can't re-lock) and unsets the
# system proxy on every network service, so all traffic flows directly with no MITM.
# Reverse it with ./restore-filtering.sh (or the "Re-enable filtering" button in the UI).
#
# Run:  sudo ./emergency-off.sh
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
MARKER="$DIR/config/emergency"
WATCHDOG_LABEL="system/com.familywebfilter.watchdog"

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

echo "Stopping the watchdog (so it can't re-enable the proxy)..."
launchctl bootout "$WATCHDOG_LABEL" 2>/dev/null || true

echo "Turning the system proxy OFF on all network services..."
while IFS= read -r svc; do
  case "$svc" in ""|\**|\(*) continue;; esac        # skip blank / disabled (*) / annotation lines
  networksetup -setwebproxystate "$svc" off 2>/dev/null || true
  networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

touch "$MARKER" 2>/dev/null || true
echo ""
echo "Done — browsing is now UNFILTERED and will stay that way until you restore it."
echo "Re-enable filtering with:  sudo $DIR/restore-filtering.sh"

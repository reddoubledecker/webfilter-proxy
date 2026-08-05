#!/bin/bash
#
# Deploy code changes from this (source) copy to the running install and restart it.
# Run from your source copy:  sudo ./deploy.sh
#
# Syncs code + UI only. It deliberately does NOT touch config/ (your live rules,
# keywords, password, learned domains, and logs live there), nor venv/ or the CA.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/usr/local/webfilter-proxy
PROXY_PLIST=/Library/LaunchDaemons/com.familywebfilter.proxy.plist

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }
[ "$SRC" != "$DEST" ] || { echo "Run this from your SOURCE copy, not $DEST." >&2; exit 1; }
[ -f "$PROXY_PLIST" ] || { echo "Not installed yet. Run install.sh at $DEST first (see README)." >&2; exit 1; }

echo "Syncing code to $DEST (config/, venv/, mitm-ca/ preserved)..."
rsync -a --delete \
  --exclude venv --exclude mitm-ca --exclude '__pycache__' --exclude config \
  "$SRC"/ "$DEST"/

echo "Restarting daemons..."
launchctl kickstart -k system/com.familywebfilter.proxy 2>/dev/null || true
launchctl kickstart -k system/com.familywebfilter.ui    2>/dev/null || true

echo "Done. Control UI: http://127.0.0.1:8788"

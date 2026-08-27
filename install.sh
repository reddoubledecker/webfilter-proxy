#!/bin/bash
#
# Family Web Filter (proxy) — installer for macOS. Sets up the venv, trusts the CA,
# installs the proxy + control-UI LaunchDaemons (root, auto-restart), and points the
# system proxy at it. Run:  sudo ./install.sh
#
# Reverse with ./uninstall.sh. Block QUIC (recommended) with ./block-quic.sh.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/venv"
CONFDIR="$DIR/mitm-ca"
CA="$CONFDIR/mitmproxy-ca-cert.pem"
PROXY_HOST=127.0.0.1; PROXY_PORT=8080; UI_PORT=8788
PROXY_PLIST=/Library/LaunchDaemons/com.familywebfilter.proxy.plist
UI_PLIST=/Library/LaunchDaemons/com.familywebfilter.ui.plist
WATCHDOG_PLIST=/Library/LaunchDaemons/com.familywebfilter.watchdog.plist

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo $0" >&2; exit 1; }

echo "[1/6] Python venv + dependencies..."
# Pick a Python >= 3.10 (mitmproxy needs it). sudo resets PATH, so check explicit paths.
PYTHON=""
for c in /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 \
         /opt/homebrew/bin/python3.10 /opt/homebrew/bin/python3 /usr/local/bin/python3 \
         python3.12 python3.11 python3; do
  p="$(command -v "$c" 2>/dev/null || true)"
  [ -n "$p" ] || continue
  if "$p" -c 'import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then
    PYTHON="$p"; break
  fi
done
[ -n "$PYTHON" ] || { echo "Need Python 3.10+. Install it with:  brew install python@3.12" >&2; exit 1; }
echo "  using $("$PYTHON" --version) at $PYTHON"
rm -rf "$VENV"                      # always rebuild clean (a half-updated venv keeps stale symlinks)
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$DIR/requirements.txt"

echo "[2/6] Generating mitmproxy CA..."
mkdir -p "$CONFDIR"
"$VENV/bin/mitmdump" --set confdir="$CONFDIR" -q >/dev/null 2>&1 &
MPID=$!
for _ in $(seq 1 40); do [ -f "$CA" ] && break; sleep 0.5; done
kill "$MPID" 2>/dev/null || true
[ -f "$CA" ] || { echo "CA generation failed" >&2; exit 1; }

echo "[3/6] Trusting CA in the System keychain..."
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA"

echo "[4/6] Installing LaunchDaemons..."
cat > "$PROXY_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.familywebfilter.proxy</string>
  <key>ProgramArguments</key><array>
    <string>$VENV/bin/mitmdump</string><string>-s</string><string>$DIR/filter.py</string>
    <string>--set</string><string>confdir=$CONFDIR</string>
    <string>--set</string><string>stream_large_bodies=1m</string>
    <string>--listen-host</string><string>127.0.0.1</string>
    <string>--listen-port</string><string>$PROXY_PORT</string><string>-q</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$DIR/config/proxy.out.log</string>
  <key>StandardErrorPath</key><string>$DIR/config/proxy.err.log</string>
</dict></plist>
PLIST

cat > "$UI_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.familywebfilter.ui</string>
  <key>ProgramArguments</key><array>
    <string>$VENV/bin/python</string><string>$DIR/control.py</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DIR/config/ui.out.log</string>
  <key>StandardErrorPath</key><string>$DIR/config/ui.err.log</string>
</dict></plist>
PLIST

cat > "$WATCHDOG_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.familywebfilter.watchdog</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string><string>$DIR/watchdog.sh</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>60</integer>
  <key>StandardOutPath</key><string>$DIR/config/watchdog.out.log</string>
  <key>StandardErrorPath</key><string>$DIR/config/watchdog.err.log</string>
</dict></plist>
PLIST

for pl in "$PROXY_PLIST" "$UI_PLIST" "$WATCHDOG_PLIST"; do
  launchctl unload "$pl" 2>/dev/null || true
  launchctl load -w "$pl"
done

echo "[5/7] Pointing the system proxy at 127.0.0.1:$PROXY_PORT..."
while IFS= read -r svc; do
  case "$svc" in ""|An\ asterisk*|\(*) continue;; esac
  networksetup -setwebproxy "$svc" "$PROXY_HOST" "$PROXY_PORT" 2>/dev/null || true
  networksetup -setsecurewebproxy "$svc" "$PROXY_HOST" "$PROXY_PORT" 2>/dev/null || true
  networksetup -setproxybypassdomains "$svc" 127.0.0.1 localhost "*.local" 2>/dev/null || true
done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

echo "[6/7] Staging the Chrome QUIC-disable profile..."
# QUIC/HTTP-3 lets Chrome bypass the proxy (e.g. YouTube/Google). macOS can't install a
# config profile silently, so we open it for a one-click approve. This is REQUIRED for
# Chrome traffic to be fully filtered.
# Also set QUIC-off at the system preference level so EVERY macOS user's Chrome picks it
# up (the profile enforces it mandatorily; this is the all-users safety net).
defaults write /Library/Preferences/com.google.Chrome QuicAllowed -bool false 2>/dev/null || true
QUIC_PROFILE="$DIR/chrome-disable-quic.mobileconfig"
if [ -f "$QUIC_PROFILE" ]; then
  sudo -u "${SUDO_USER:-$USER}" open "$QUIC_PROFILE" 2>/dev/null || open "$QUIC_PROFILE" 2>/dev/null || true
  echo "  -> Approve it now (as a Device profile): System Settings > General > Device Management."
else
  echo "  (profile not found; install chrome-disable-quic.mobileconfig manually)"
fi

echo "[7/7] Done."
echo
echo "  Control UI:   http://127.0.0.1:$UI_PORT   (set a password on first visit)"
echo "  IMPORTANT:    approve the Chrome QUIC profile (opened above), then fully quit"
echo "                and reopen Chrome — otherwise YouTube/Google bypass the filter."
echo "  Remove:       sudo $DIR/uninstall.sh"

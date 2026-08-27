#!/bin/bash
#
# Family Web Filter watchdog. Runs every INTERVAL seconds (LaunchDaemon StartInterval).
# Keeps the proxy alive; if it can't be revived within THRESHOLD_SECS, FAILS OPEN
# (restores unfiltered internet + alerts) so a crash never bricks the machine, and
# automatically RE-LOCKS the moment the proxy recovers.
#
# Deliberately avoids `set -e`/pipefail so a single failing command never aborts the
# self-repair logic.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8080
UI_PORT=8788
INTERVAL=60                 # must match the plist StartInterval
THRESHOLD_SECS=180          # fail open after the proxy has been down this long

STATE="$DIR/config"
FAILS_FILE="$STATE/watchdog.fails"
FAILOPEN_FILE="$STATE/watchdog.failopen"
WEDGED_FILE="$STATE/watchdog.wedged"
LOG="$STATE/watchdog.log"

PROXY_LABEL="system/com.familywebfilter.proxy"
UI_LABEL="system/com.familywebfilter.ui"
PROXY_PLIST="/Library/LaunchDaemons/com.familywebfilter.proxy.plist"
UI_PLIST="/Library/LaunchDaemons/com.familywebfilter.ui.plist"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG" 2>/dev/null; }

listening() {   # $1 = port; returns 0 if something accepts a TCP connect on 127.0.0.1
  /usr/bin/python3 - "$1" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); sys.exit(0)
except Exception:
    sys.exit(1)
PY
}

http_ok() {     # $1 = proxy port; returns 0 only if the proxy actually SERVES an HTTP
                # response (not just that the port is open). Detects a wedged proxy that
                # a bare TCP connect would wrongly report as healthy. Fully local traffic:
                # it asks the proxy to fetch the control UI; even a 502 (UI down) proves
                # the proxy is processing. Generous timeout so a slow old Mac isn't misjudged.
  /usr/bin/python3 - "$1" "$UI_PORT" <<'PY' >/dev/null 2>&1
import socket, sys
port, ui = int(sys.argv[1]), int(sys.argv[2])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(8)
    req = ("GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Proxy-Connection: close\r\nConnection: close\r\n\r\n" % (ui, ui))
    s.sendall(req.encode())
    data = s.recv(16)
    s.close()
    sys.exit(0 if data[:5] == b"HTTP/" else 1)
except Exception:
    sys.exit(1)
PY
}

notify() {      # best-effort desktop alert to the logged-in user
  local uid; uid=$(stat -f%u /dev/console 2>/dev/null)
  [ -n "${uid:-}" ] && launchctl asuser "$uid" /usr/bin/osascript \
    -e "display notification \"$1\" with title \"Family Web Filter\"" >/dev/null 2>&1 || true
}

each_service() {   # run "$1 <service>" for every real (non-disabled) network service
  while IFS= read -r svc; do
    case "$svc" in ""|An\ asterisk*|\(*) continue;; esac
    "$1" "$svc"
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
}
proxy_on()  { networksetup -setwebproxy "$1" 127.0.0.1 "$PORT" 2>/dev/null; networksetup -setsecurewebproxy "$1" 127.0.0.1 "$PORT" 2>/dev/null; }
proxy_off() { networksetup -setwebproxystate "$1" off 2>/dev/null; networksetup -setsecurewebproxystate "$1" off 2>/dev/null; }

restart() { launchctl kickstart -k "$1" 2>/dev/null || launchctl bootstrap system "$2" 2>/dev/null || true; }

# Keep the control UI alive too (non-critical — never fail open for it).
listening "$UI_PORT" || restart "$UI_LABEL" "$UI_PLIST"

# ── Proxy health ─────────────────────────────────────────────────────────────────
# Healthy = the port is open AND the proxy actually serves a request. If it's listening
# but unresponsive (wedged — common on a low-spec Mac under load), a bare TCP check would
# call it healthy forever and you'd have to reboot. We catch that and restart it.
if listening "$PORT" && http_ok "$PORT"; then
  echo 0 > "$FAILS_FILE" 2>/dev/null
  rm -f "$WEDGED_FILE" 2>/dev/null
  if [ -f "$FAILOPEN_FILE" ]; then                 # recovered from a fail-open window
    log "proxy recovered -> re-enabling system proxy (re-lock)"
    each_service proxy_on
    rm -f "$FAILOPEN_FILE"
    notify "Filter restored - traffic is protected again."
  fi
  exit 0
fi

# Listening but not serving = wedged. Give it one grace cycle (a single slow moment on an
# old Mac shouldn't trigger a restart); restart only if it's still wedged next time.
if listening "$PORT"; then
  wedged=$(( $(cat "$WEDGED_FILE" 2>/dev/null || echo 0) + 1 ))
  echo "$wedged" > "$WEDGED_FILE" 2>/dev/null
  if [ "$wedged" -lt 2 ]; then
    log "proxy listening but UNRESPONSIVE (strike $wedged) - rechecking next cycle"
    exit 0
  fi
  log "proxy WEDGED (listening but not serving) - forcing restart"
else
  rm -f "$WEDGED_FILE" 2>/dev/null                 # genuinely down, not wedged
fi

# Proxy is DOWN or WEDGED — try to revive it.
fails=$(( $(cat "$FAILS_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$fails" > "$FAILS_FILE" 2>/dev/null
log "proxy DOWN (failure #$fails) - attempting restart"
restart "$PROXY_LABEL" "$PROXY_PLIST"
sleep 3
if listening "$PORT" && http_ok "$PORT"; then
  log "restart succeeded"
  echo 0 > "$FAILS_FILE" 2>/dev/null
  rm -f "$WEDGED_FILE" 2>/dev/null
  exit 0
fi

# Restart didn't take — capture a meaningful diagnosis (once, at the start of the outage).
if [ "$fails" -eq 1 ]; then
  log "restart failed - writing diagnosis to health.log"
  bash "$DIR/doctor.sh" --log >/dev/null 2>&1 || true
fi

# Still down after a restart attempt — fail open once we've been down long enough.
down_secs=$(( fails * INTERVAL ))
if [ "$down_secs" -ge "$THRESHOLD_SECS" ] && [ ! -f "$FAILOPEN_FILE" ]; then
  log "down ${down_secs}s >= ${THRESHOLD_SECS}s -> FAIL OPEN (restoring unfiltered internet)"
  each_service proxy_off
  touch "$FAILOPEN_FILE"
  notify "Filter is DOWN - internet is temporarily UNFILTERED. It will re-lock automatically when the filter recovers."
fi
exit 0

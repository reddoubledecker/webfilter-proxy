#!/bin/bash
#
# Family Web Filter health check. Prints each component's status with a concrete fix for
# anything wrong. Run:  sudo ./doctor.sh    (some checks need root)
#   --log   also write the report to config/health.log (used by the watchdog on incidents)
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/venv"
CONFDIR="$DIR/mitm-ca"
PROXY_ERR="$DIR/config/proxy.err.log"
HEALTH_LOG="$DIR/config/health.log"
PORT=8080; UI_PORT=8788
FAIL=0; WARN=0

pass() { echo "  [ OK ]  $1"; }
warn() { echo "  [WARN]  $1"; echo "          -> $2"; WARN=$((WARN+1)); }
fail() { echo "  [FAIL]  $1"; echo "          -> $2"; FAIL=$((FAIL+1)); }

listening() { /usr/bin/python3 -c "import socket,sys
s=socket.socket(); s.settimeout(1)
try: s.connect(('127.0.0.1',int(sys.argv[1]))); sys.exit(0)
except Exception: sys.exit(1)" "$1" 2>/dev/null; }

serves() {   # proxy port is not just open but actually answers an HTTP request (catches a wedged proxy)
  /usr/bin/python3 -c "import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=8); s.settimeout(8)
    s.sendall(('GET http://127.0.0.1:%s/ HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n'%(sys.argv[2],sys.argv[2])).encode())
    sys.exit(0 if s.recv(16)[:5]==b'HTTP/' else 1)
except Exception: sys.exit(1)" "$1" "$UI_PORT" 2>/dev/null; }

classify_proxy_error() {   # reads the tail of proxy.err.log and suggests the likely fix
  local t; t=$(tail -40 "$PROXY_ERR" 2>/dev/null)
  case "$t" in
    *"address already in use"*)
      echo "Port $PORT is held by another process. Check: sudo lsof -nP -iTCP:$PORT ; fix: kill it or reboot.";;
    *"serial number which wasn't positive"*|*"serial number"*)
      echo "The mitmproxy CA has an invalid serial (newer 'cryptography' rejects it). Fix: sudo ./regenerate-ca.sh";;
    *"Operation not permitted"*|*"pyvenv.cfg"*)
      echo "Root can't read the install dir (macOS TCC/permissions). Fix: ensure the install directory is readable by root.";;
    *"ModuleNotFoundError"*|*"No module named"*)
      echo "A Python dependency/venv is broken. Fix: re-run ./install.sh from the install directory (rebuilds the venv).";;
    *"SyntaxError"*|*"IndentationError"*)
      echo "A code error in a .py file. Fix: check the traceback in proxy.err.log; re-deploy known-good code.";;
    *Traceback*|*Error*)
      echo "The proxy crashed. Check: sudo tail -40 $PROXY_ERR (share the traceback).";;
    *)
      echo "No obvious cause in the log. Check: sudo tail -40 $PROXY_ERR";;
  esac
}

report() {
  echo "Family Web Filter - health check ($(date '+%Y-%m-%d %H:%M:%S'))"
  echo ""

  # Python venv
  if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import sys;exit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then
    pass "Python venv ($("$VENV/bin/python" --version 2>&1))"
  else
    fail "Python venv missing or too old" "Rebuild it: cd $DIR && sudo ./install.sh"
  fi

  # Dependencies
  if "$VENV/bin/python" -c 'import mitmproxy, flask' 2>/dev/null; then
    pass "Dependencies (mitmproxy, flask) installed"
  else
    fail "Dependencies missing" "cd $DIR && sudo ./install.sh  (reinstalls requirements)"
  fi

  # Proxy listening AND serving (a wedged proxy is listening but won't answer)
  if ! listening "$PORT"; then
    fail "Proxy is NOT listening on $PORT" "$(classify_proxy_error) | then: sudo launchctl kickstart -k system/com.familywebfilter.proxy"
  elif serves "$PORT"; then
    pass "Proxy is listening and serving on 127.0.0.1:$PORT"
  else
    fail "Proxy is listening but NOT responding (wedged)" "Restart it: sudo launchctl kickstart -k system/com.familywebfilter.proxy  (the watchdog now auto-restarts this too)"
  fi

  # Control UI listening
  if listening "$UI_PORT"; then
    pass "Control UI is listening on 127.0.0.1:$UI_PORT"
  else
    warn "Control UI is not listening on $UI_PORT" "sudo launchctl kickstart -k system/com.familywebfilter.ui"
  fi

  # LaunchDaemons loaded (needs root)
  if [ "$(id -u)" -eq 0 ]; then
    for lbl in proxy ui watchdog; do
      if launchctl print "system/com.familywebfilter.$lbl" >/dev/null 2>&1; then
        pass "Daemon loaded: com.familywebfilter.$lbl"
      else
        fail "Daemon NOT loaded: com.familywebfilter.$lbl" "sudo launchctl bootstrap system /Library/LaunchDaemons/com.familywebfilter.$lbl.plist (or reboot)"
      fi
    done
  else
    warn "Skipped daemon-load checks (need root)" "Re-run with: sudo $0"
  fi

  # System proxy pointed at us
  if scutil --proxy 2>/dev/null | grep -q "HTTPSProxy : 127.0.0.1"; then
    pass "System proxy points at 127.0.0.1"
  else
    warn "System proxy is NOT set to 127.0.0.1:$PORT (traffic is unfiltered)" \
      "sudo networksetup -setsecurewebproxy \"Wi-Fi\" 127.0.0.1 $PORT ; and -setwebproxy the same"
  fi

  # CA present + actually trusted as a root (verify the trust chain, not just presence)
  CACERT="$CONFDIR/mitmproxy-ca-cert.pem"
  FIXCA="sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CACERT"
  if [ ! -f "$CACERT" ]; then
    fail "mitmproxy CA missing" "sudo ./regenerate-ca.sh  (creates + trusts a fresh CA)"
  elif security verify-cert -L -p basic -c "$CACERT" >/dev/null 2>&1; then
    pass "mitmproxy CA is present and trusted as a root"
  elif security find-certificate -c mitmproxy /Library/Keychains/System.keychain >/dev/null 2>&1; then
    warn "CA is in the System keychain but NOT trusted as a root (HTTPS will error)" "$FIXCA"
  else
    warn "CA present on disk but not added to the System keychain (HTTPS will error)" "$FIXCA"
  fi

  # QUIC disabled (Chrome bypasses the proxy otherwise)
  if defaults read /Library/Preferences/com.google.Chrome QuicAllowed 2>/dev/null | grep -q 0 \
     || profiles list 2>/dev/null | grep -qi noquic; then
    pass "Chrome QUIC is disabled"
  else
    warn "Chrome QUIC may be enabled (YouTube/Google can bypass the proxy)" \
      "sudo defaults write /Library/Preferences/com.google.Chrome QuicAllowed -bool false ; install the chrome-disable-quic profile; restart Chrome"
  fi

  # Fail-open state
  if [ -f "$DIR/config/watchdog.failopen" ]; then
    warn "Currently FAILED OPEN - internet is unfiltered" \
      "The proxy is down; it re-locks automatically when the proxy recovers. Fix the proxy (see above)."
  fi

  # Emergency bypass
  if [ -f "$DIR/config/emergency" ]; then
    warn "Emergency bypass is ACTIVE - filtering is OFF and the watchdog is stopped" \
      "Re-enable when fixed: sudo ./restore-filtering.sh (or the UI Settings > Emergency button)"
  fi

  # config.json perms
  if [ -f "$DIR/config/config.json" ]; then
    m=$(stat -f%p "$DIR/config/config.json" 2>/dev/null | tail -c 4)
    [ "$m" = "600" ] && pass "config.json is root-only (600)" \
      || warn "config.json is not 600 (password hash readable by other users)" "sudo chmod 600 $DIR/config/config.json"
  fi

  # Activity log size
  sz=$(du -m "$DIR/config/activity.log" 2>/dev/null | cut -f1)
  [ -n "${sz:-}" ] && [ "$sz" -ge 90 ] && warn "activity.log is ${sz}MB (rotates at 100MB)" "Normal; it rotates automatically."

  # Recent application-level filtering errors (each already carries a FIX line)
  ERRLOG="$DIR/config/filter-errors.log"
  if [ -s "$ERRLOG" ]; then
    recent=$(grep -c "FIX:" "$ERRLOG" 2>/dev/null)
    warn "filter-errors.log has logged errors ($recent with a fix hint)" \
      "Read them: tail -30 $ERRLOG  (each entry says what to check and how to fix)"
    echo "          last error:"
    grep -A2 "^[0-9].*in " "$ERRLOG" 2>/dev/null | tail -4 | sed 's/^/            /'
  fi

  echo ""
  echo "Summary: $FAIL failed, $WARN warnings."
  [ "$FAIL" -eq 0 ] && echo "Everything critical looks healthy." || echo "Fix the [FAIL] items above (each has a '->' fix)."
}

OUT="$(report)"
echo "$OUT"
if [ "${1:-}" = "--log" ]; then
  { echo "===================================================================="; echo "$OUT"; } >> "$HEALTH_LOG" 2>/dev/null || true
fi
[ "$FAIL" -eq 0 ]

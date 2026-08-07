"""Web Filter — mitmproxy addon.

Run with:  mitmdump -s filter.py

  request()  — SafeSearch, learned domains, URL rules + URL keywords
  response() — page-content keywords + category scoring; logs EVERY request (allowed +
               blocked, with search queries) to a rotating activity log.
Config is hot-reloaded from config/ so the control UI's edits apply live.
"""
import os
import sys
import json
import time
import secrets
import asyncio
import logging
import logging.handlers
import datetime
import traceback
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # so mitmdump finds our modules

from mitmproxy import ctx, http

import filterlib as F
import categorize as C

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

# ── Rotating activity log (all traffic, 100 MB rotation, 30-day retention) ────────
_alog = logging.getLogger("wf.activity")
_alog.setLevel(logging.INFO)
_alog.propagate = False
if not _alog.handlers:                       # guard against duplicate handlers on script reload
    _ah = logging.handlers.RotatingFileHandler(
        F.ACTIVITY_LOG, maxBytes=F.ACTIVITY_MAX_BYTES, backupCount=F.ACTIVITY_BACKUPS, encoding="utf-8")
    _ah.setFormatter(logging.Formatter("%(message)s"))
    _alog.addHandler(_ah)
_count = 0

# ── Error log (application-level filtering errors, with remediation hints) ─────────
# The request/response hooks swallow exceptions so a filtering bug never breaks browsing,
# but the error must not vanish silently — it lands here in plain English, with a hint on
# what to check and how to fix it. Throttled per unique error so a hot path can't flood it.
ERROR_LOG = os.path.join(os.path.dirname(F.ACTIVITY_LOG), "filter-errors.log")
_elog = logging.getLogger("wf.errors")
_elog.setLevel(logging.ERROR)
_elog.propagate = False
if not _elog.handlers:
    _eh = logging.handlers.RotatingFileHandler(
        ERROR_LOG, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    _eh.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%Y-%m-%d %H:%M:%S"))
    _elog.addHandler(_eh)
_err_seen = {}          # signature -> (last_logged_epoch, suppressed_count)
_ERR_THROTTLE = 60      # seconds; identical errors within this window are counted, not re-logged


def _hint(exc):
    """Plain-English 'what to check / how to fix' for a caught exception."""
    m = ("%s %s" % (type(exc).__name__, exc)).lower()
    if "address already in use" in m or "errno 48" in m:
        return "Port 8080 is taken by another process. Check: sudo lsof -nP -iTCP:8080 — kill it or reboot."
    if "serial" in m:
        return "The mitmproxy CA has an invalid serial. Fix: run ./regenerate-ca.sh from the install directory (as root)."
    if isinstance(exc, PermissionError) or "operation not permitted" in m:
        return "A file couldn't be read (macOS TCC/permissions). Check the install directory is readable by root and the daemons run as root."
    if isinstance(exc, (ImportError, ModuleNotFoundError)):
        return "A Python dependency is missing. Fix: re-run ./install.sh from the install directory (as root)."
    if isinstance(exc, (json.JSONDecodeError, ValueError)) and "json" in m:
        return "A config/*.json file is malformed. Check config/ for the offending file; restore from config.example.json or a backup."
    if isinstance(exc, MemoryError):
        return "Out of memory. Check the page size / activity.log growth; restart the proxy."
    return "Unexpected filtering error. Run ./doctor.sh; if it persists, re-deploy known-good code and check filter-errors.log."


def _log_error(where, exc, flow=None):
    """Log a caught error once per unique (where,type) within the throttle window, with the
    request URL, the reason, a fix hint, and the traceback. Never raises."""
    try:
        sig = "%s:%s" % (where, type(exc).__name__)
        now = time.time()
        last, suppressed = _err_seen.get(sig, (0, 0))
        if now - last < _ERR_THROTTLE:
            _err_seen[sig] = (last, suppressed + 1)
            return
        url = ""
        try:
            url = flow.request.pretty_url if flow else ""
        except Exception:
            pass
        extra = " (%d more suppressed in the last %ds)" % (suppressed, _ERR_THROTTLE) if suppressed else ""
        _elog.error(
            "in %s: %s: %s%s\n    url: %s\n    FIX: %s\n%s",
            where, type(exc).__name__, exc, extra, url or "-", _hint(exc),
            "    " + traceback.format_exc().replace("\n", "\n    ").rstrip())
        _err_seen[sig] = (now, 0)
    except Exception:
        pass                                      # logging must never itself break the proxy


F.prune_old_logs()


def _write(rec):
    global _count
    _alog.info(json.dumps(rec, ensure_ascii=False))
    _count += 1
    if _count % 5000 == 0:
        F.prune_old_logs()


class WebFilter:
    def __init__(self):
        self._bypass_applied = None
        self._task = None

    def running(self):
        self._apply_bypass()
        self._task = asyncio.ensure_future(self._ticker())

    def done(self):
        t = getattr(self, "_task", None)
        if t:
            t.cancel()                            # clean shutdown (no "Task pending" noise)

    async def _ticker(self):
        # Re-apply config every 2s regardless of traffic. Essential for bypass-all: once
        # everything is ignored, request hooks stop firing, so this is how the proxy notices
        # the switch being turned back OFF.
        try:
            while True:
                await asyncio.sleep(2)
                try:
                    F.maybe_reload()
                    self._apply_bypass()
                    F.flush_suggestions()
                except Exception as e:
                    _log_error("ticker", e)
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _parent_host(flow):
        for h in ("referer", "origin"):
            v = flow.request.headers.get(h)
            if v:
                try:
                    host = urlparse(v).hostname
                    if host:
                        return host.lower()
                except ValueError:
                    pass
        return None

    def _apply_bypass(self):
        """Set mitmproxy's ignore_hosts (no-intercept passthrough). In bypass-all testing
        mode, ignore EVERYTHING; otherwise just the configured bypass list."""
        rx = ["."] if F.bypass_all() else F.bypass_regexes()
        if rx != self._bypass_applied:
            try:
                ctx.options.update(ignore_hosts=rx)
                self._bypass_applied = rx
            except Exception as e:
                _log_error("apply_bypass", e)

    def request(self, flow: http.HTTPFlow):
        try:
            self._request(flow)
        except Exception as e:
            _log_error("request", e, flow)        # log it, but never break browsing

    def _request(self, flow: http.HTTPFlow):
        F.maybe_reload()
        self._apply_bypass()                     # re-apply if the bypass list changed
        if flow.request.host in LOCAL_HOSTS:
            return

        # Suggest related domains: if this cross-site request was referred by a bypassed
        # site, record its domain so the parent can add it to the bypass bundle.
        parent = self._parent_host(flow)
        if parent and F.host_bypassed(parent):
            F.add_suggestion(flow.request.host, parent)
        F.flush_suggestions()                    # throttled

        if F.bypass_all():                        # testing: no filtering/SafeSearch (still logs)
            return

        url = flow.request.pretty_url

        if F.safe_search_enabled():
            p = F.safe_search_param(url)
            if p:
                flow.request.query[p[0]] = p[1]

        rec = F.match_learned(url)
        if rec:
            return self._block(flow, "Auto-detected: " + rec["label"])

        status, reason = F.evaluate_request(url)
        if status == "block":
            return self._block(flow, reason)
        if status == "allow":
            flow.metadata["wf_allow"] = True

    def response(self, flow: http.HTTPFlow):
        try:
            self._response(flow)
        except Exception as e:
            _log_error("response", e, flow)

    def _response(self, flow: http.HTTPFlow):
        if flow.request.host in LOCAL_HOSTS:
            return
        is_html = "text/html" in flow.response.headers.get("content-type", "").lower()
        text = None
        if is_html:
            try:
                text = flow.response.get_text()
            except Exception:
                text = None

        # Content checks (only if not already decided, and not in bypass-all testing mode).
        if text and not flow.metadata.get("wf_blocked") and not flow.metadata.get("wf_allow") and not F.bypass_all():
            status, reason = F.evaluate_content(text)
            if status == "block":
                self._block_response(flow, reason)
            else:
                hit = F.top_blockable(C.score_signals(C.extract_signals(text, flow.request.pretty_url)))
                if hit:
                    F.add_learned(flow.request.host, hit["category"], hit["label"], hit["score"])
                    self._block_response(flow, "Auto-detected: " + hit["label"])

        # Inject the "monitored" banner into non-blocked top-level HTML documents.
        if (text is not None and not flow.metadata.get("wf_blocked") and F.banner_enabled()
                and flow.request.headers.get("Sec-Fetch-Dest", "") == "document"):
            self._inject_banner(flow, text)

        self._log(flow)

    def _inject_banner(self, flow, text):
        nonce = secrets.token_urlsafe(12)
        low = text.lower()
        idx = low.rfind("</body>")
        if idx == -1:
            idx = low.rfind("</html>")
        snippet = F.banner_snippet(nonce)
        flow.response.set_text(text[:idx] + snippet + text[idx:] if idx != -1 else text + snippet)
        csp = flow.response.headers.get("content-security-policy")
        if csp:
            flow.response.headers["content-security-policy"] = F.csp_with_nonce(csp, nonce)

    # ── block helpers (set metadata; the single _log call records it) ─────────
    def _block(self, flow, reason):
        flow.metadata["wf_blocked"] = True
        flow.metadata["wf_reason"] = reason
        flow.response = http.Response.make(
            403, F.blocked_page(reason, flow.request.pretty_url).encode(),
            {"Content-Type": "text/html; charset=utf-8"})

    def _block_response(self, flow, reason):
        flow.metadata["wf_blocked"] = True
        flow.metadata["wf_reason"] = reason
        flow.response.status_code = 403
        flow.response.headers["Content-Type"] = "text/html; charset=utf-8"
        flow.response.set_text(F.blocked_page(reason, flow.request.pretty_url))

    # ── logging ───────────────────────────────────────────────────────────────
    def _log(self, flow):
        url = flow.request.pretty_url
        blocked = bool(flow.metadata.get("wf_blocked"))
        _write({
            "t": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": "blocked" if blocked else "allowed",
            "reason": flow.metadata.get("wf_reason", "") if blocked else "",
            "host": flow.request.host,
            "url": url,
            "query": F.search_query(url) or "",
            "dest": flow.request.headers.get("Sec-Fetch-Dest", ""),
        })


addons = [WebFilter()]

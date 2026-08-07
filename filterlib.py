"""Filtering engine for the Web Filter proxy — no mitmproxy dependency, so it's unit-
testable and shared by the proxy (filter.py) and the control UI (control.py).

Config lives in config/: rules.json, keywords.txt, config.json, learned.json. The proxy
hot-reloads them (mtime watch) so UI edits apply live."""
import os
import re
import json
import time
import base64
import hashlib
import hmac
import secrets
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(HERE, "config")
RULES_PATH = os.path.join(CONFIG_DIR, "rules.json")
KEYWORDS_PATH = os.path.join(CONFIG_DIR, "keywords.txt")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LEARNED_PATH = os.path.join(CONFIG_DIR, "learned.json")

DEFAULT_CONFIG = {"threshold": 40, "safeSearch": True, "banner": True, "bypassAll": False,
                  "categories": {}, "bypass": [], "passwordHash": None, "passwordSalt": None}

# ── Loaders ──────────────────────────────────────────────────────────────────────

def _load_keywords(path):
    out, seen = [], set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                k = line.strip().lower()
                if len(k) >= 2 and k not in seen:
                    seen.add(k); out.append(k)
    except OSError:
        pass
    return out

def _load_rules(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [r for r in json.load(f).get("rules", []) if r.get("pattern")]
    except (OSError, ValueError):
        return []

def _load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    except (OSError, ValueError):
        return dict(DEFAULT_CONFIG)

# ── Hot-reloadable state ─────────────────────────────────────────────────────────

RULES, KEYWORDS, _KW_CONTENT, CONFIG = [], [], [], dict(DEFAULT_CONFIG)
_mtimes, _last_check = {}, 0.0

def reload_config():
    global RULES, KEYWORDS, _KW_CONTENT, CONFIG
    RULES = _load_rules(RULES_PATH)
    KEYWORDS = _load_keywords(KEYWORDS_PATH)
    _KW_CONTENT = [(k, re.compile(r"\b" + re.escape(k) + r"\b")) for k in KEYWORDS]
    CONFIG = _load_config(CONFIG_PATH)

def _mtime(p):
    try:
        return os.path.getmtime(p)
    except OSError:
        return 0

def maybe_reload():
    """Cheap mtime check (throttled) — reloads config files if they changed on disk."""
    global _last_check
    now = time.time()
    if now - _last_check < 2:
        return
    _last_check = now
    changed = False
    for p in (RULES_PATH, KEYWORDS_PATH, CONFIG_PATH):
        m = _mtime(p)
        if _mtimes.get(p) != m:
            _mtimes[p] = m; changed = True
    if changed:
        reload_config()
    ml = _mtime(LEARNED_PATH)                     # learned.json is written by whichever process
    if _mtimes.get(LEARNED_PATH) != ml:          # detects a page; reload so both stay current
        _mtimes[LEARNED_PATH] = ml
        reload_learned()

reload_config()
for _p in (RULES_PATH, KEYWORDS_PATH, CONFIG_PATH, LEARNED_PATH):
    _mtimes[_p] = _mtime(_p)

# ── Pattern matching ─────────────────────────────────────────────────────────────

def matches(url, pattern):
    p = re.sub(r"^https?://", "", pattern.strip().lower())
    if not p:
        return False
    u = urlparse(url)
    host = (u.hostname or "").lower()
    test = (host + u.path + (("?" + u.query) if u.query else "")).lower()
    if "*" not in p:
        dom = re.sub(r"^www\.", "", p.split("/")[0])
        path = p[p.index("/"):] if "/" in p else ""
        hm = host == dom or host.endswith("." + dom)
        return (hm and (dom + path) in test) if path else hm
    if p.startswith("*."):
        d = re.sub(r"^www\.", "", p[2:])
        return host == d or host.endswith("." + d)
    if re.match(r"^[\w.-]+\.\*$", p):
        b = re.sub(r"^www\.", "", p[:-2])
        return host == b or host.startswith(b + ".")
    rx = "^" + re.escape(p).replace(r"\*", ".*") + "$"
    try:
        return re.match(rx, test) is not None or re.match(rx, host) is not None
    except re.error:
        return False

def specificity(pattern):
    p = re.sub(r"^https?://", "", pattern.strip().lower())
    return sum(1 for c in p if c != "*")

def resolve_rules(url):
    best = None
    for rule in RULES:
        if not matches(url, rule["pattern"]):
            continue
        typ = "allow" if rule.get("type") == "allow" else "block"
        spec = specificity(rule["pattern"])
        if best is None or spec > best[2] or (spec == best[2] and typ == "allow"):
            best = (typ, rule["pattern"], spec)
    return (best[0], best[1]) if best else None

def url_keyword(url):
    u = urlparse(url)
    hay = ((u.hostname or "") + u.path + (("?" + u.query) if u.query else "")).lower()
    return next((k for k in KEYWORDS if k in hay), None)

def content_keyword(text, limit=200000):
    hay = text[:limit].lower()
    return next((k for k, rx in _KW_CONTENT if rx.search(hay)), None)

# ── Config accessors ─────────────────────────────────────────────────────────────

def threshold():
    return int(CONFIG.get("threshold", 40))

def safe_search_enabled():
    return bool(CONFIG.get("safeSearch", True))

def banner_enabled():
    return bool(CONFIG.get("banner", True))

def bypass_all():
    """Testing switch: when on, pass everything through (no blocking/SafeSearch), still logs."""
    return bool(CONFIG.get("bypassAll", False))

def is_failopen():
    """True if the watchdog has failed open (proxy down long enough to restore internet)."""
    return os.path.exists(os.path.join(CONFIG_DIR, "watchdog.failopen"))

def proxy_listening(port=8080):
    import socket
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()

def category_enabled(cid):
    return (CONFIG.get("categories") or {}).get(cid, True)   # default on

# ── Bypass (no-intercept passthrough) ────────────────────────────────────────────
# Hosts matching the bypass list are tunnelled through WITHOUT interception — not
# decrypted, filtered, or logged. Use for cert-pinned sites/apps (banking, etc.) that
# break under the MITM. Fed to mitmproxy's ignore_hosts option (regex over host:port).

def bypass_entries():
    """Normalized bypass list as [{'pattern','group'}] (accepts legacy plain strings)."""
    out = []
    for e in (CONFIG.get("bypass") or []):
        if isinstance(e, str):
            out.append({"pattern": e.strip().lower(), "group": ""})
        elif isinstance(e, dict) and e.get("pattern"):
            out.append({"pattern": str(e["pattern"]).strip().lower(),
                        "group": (e.get("group") or "").strip()})
    return [e for e in out if e["pattern"]]

def bypass_list():
    return [e["pattern"] for e in bypass_entries()]

def _pattern_to_regex(p):
    if "*" in p:                                   # wildcard: *bank* -> .*bank.*
        return re.escape(p).replace(r"\*", ".*")
    if "." in p:                                   # domain: example.com + subdomains
        return r"(^|\.)" + re.escape(p) + r"(:\d+)?$"
    return re.escape(p)                            # bare keyword: substring match

def bypass_regexes():
    return [_pattern_to_regex(p) for p in bypass_list() if p]

def host_bypassed(host):
    host = (host or "").lower()
    if not host:
        return False
    return any(re.search(r, host) for r in bypass_regexes())

def group_for_host(host):
    """Group name of the bypass entry that matches this host, or '' — used to keep
    suggested related domains in the same group as their parent site."""
    host = (host or "").lower()
    for e in bypass_entries():
        if re.search(_pattern_to_regex(e["pattern"]), host):
            return e["group"]
    return ""

# ── Bypass bundles (presets) ─────────────────────────────────────────────────────

BUNDLES_PATH = os.path.join(HERE, "bundles.json")

def bundles():
    try:
        with open(BUNDLES_PATH, encoding="utf-8") as f:
            return json.load(f).get("bundles", {})
    except (OSError, ValueError):
        return {}

# ── "Suggest related domains" for bypassed sites ─────────────────────────────────
# When a bypassed site (e.g. netflix.com) pulls content from another domain
# (nflxvideo.net), that sub-resource request carries Referer/Origin = the bypassed
# site. We collect those cross-site domains as SUGGESTIONS for the parent to review
# and add to bypass. Used only for suggestions (never to allow), so a spoofed Referer
# can at worst create a suggestion the parent ignores.

SUGGESTIONS_PATH = os.path.join(CONFIG_DIR, "suggestions.json")
SUGGEST_STALE_DAYS = 7
_suggest_delta = {}          # domain -> {"parents": set(), "count": int} since last flush
_suggest_last_flush = 0.0

def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default

def _save_json(path, data):
    try:
        _atomic_write(path, json.dumps(data, indent=2))
    except OSError:
        pass

def base_domain(host):
    parts = (host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")

def add_suggestion(req_host, parent_host):
    d = base_domain(req_host)
    if not d or host_bypassed(req_host):
        return
    e = _suggest_delta.setdefault(d, {"parents": set(), "count": 0})
    e["parents"].add(parent_host)
    e["count"] += 1

def flush_suggestions(force=False):
    """Merge the in-memory delta into suggestions.json (throttled). Prunes bypassed/stale."""
    global _suggest_last_flush
    import datetime
    now = time.time()
    if not force and (now - _suggest_last_flush < 10 or not _suggest_delta):
        return
    _suggest_last_flush = now
    data = _load_json(SUGGESTIONS_PATH, {})
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    for d, e in _suggest_delta.items():
        rec = data.get(d, {"domain": d, "parents": [], "count": 0})
        rec["count"] += e["count"]
        rec["parents"] = sorted(set(rec.get("parents", [])) | e["parents"])
        rec["lastSeen"] = ts
        data[d] = rec
    _suggest_delta.clear()
    cutoff = now - SUGGEST_STALE_DAYS * 86400
    for d in list(data):
        stale = False
        try:
            stale = datetime.datetime.fromisoformat(data[d].get("lastSeen", "")).timestamp() < cutoff
        except ValueError:
            pass
        if host_bypassed(d) or stale:
            del data[d]
    _save_json(SUGGESTIONS_PATH, data)

def list_suggestions():
    data = _load_json(SUGGESTIONS_PATH, {})
    return sorted(data.values(), key=lambda r: r.get("count", 0), reverse=True)

def dismiss_suggestion(domain):
    data = _load_json(SUGGESTIONS_PATH, {})
    if data.pop(domain, None) is not None:
        _save_json(SUGGESTIONS_PATH, data)

# ── Decisions ────────────────────────────────────────────────────────────────────

def evaluate_request(url):
    """('block', reason) | ('allow', None) | (None, None)."""
    d = resolve_rules(url)
    if d:
        return ("allow", None) if d[0] == "allow" else ("block", "Rule: " + d[1])
    kw = url_keyword(url)
    return ("block", "Keyword: " + kw) if kw else (None, None)

def evaluate_content(text):
    kw = content_keyword(text)
    return ("block", "Keyword: " + kw) if kw else (None, None)

def top_blockable(ranked):
    """First category hit that is enabled and over threshold."""
    th = threshold()
    for r in ranked:
        if r["score"] >= th and category_enabled(r["category"]):
            return r
    return None

# ── SafeSearch ───────────────────────────────────────────────────────────────────

_SAFE_SEARCH = [
    (lambda h, u: re.search(r"(^|\.)google\.[a-z.]+$", h) and u.path.startswith("/search"), "safe", "active"),
    (lambda h, u: re.search(r"(^|\.)bing\.com$", h) and u.path.startswith("/search"), "adlt", "strict"),
    (lambda h, u: re.search(r"(^|\.)duckduckgo\.com$", h) and "q" in parse_qs(u.query), "kp", "1"),
]

def safe_search_param(url):
    u = urlparse(url)
    host = (u.hostname or "").lower()
    q = parse_qs(u.query, keep_blank_values=True)
    for match, param, val in _SAFE_SEARCH:
        if match(host, u):
            return None if q.get(param, [None])[0] == val else (param, val)
    return None

# ── Learned domains ──────────────────────────────────────────────────────────────

def _load_learned():
    try:
        with open(LEARNED_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

LEARNED = _load_learned()

def reload_learned():
    global LEARNED
    LEARNED = _load_learned()

def _save_learned():
    try:
        with open(LEARNED_PATH, "w", encoding="utf-8") as f:
            json.dump(LEARNED, f, indent=2)
    except OSError:
        pass

def match_learned(url):
    host = (urlparse(url).hostname or "").lower()
    for key, rec in LEARNED.items():
        if host == key or host.endswith("." + key):
            return rec
    return None

def add_learned(host, category, label, score):
    host = re.sub(r"^www\.", "", (host or "").lower())
    if host:
        reload_learned()          # merge with any UI-side deletions before writing
        LEARNED[host] = {"host": host, "category": category, "label": label, "score": score}
        _save_learned()

def delete_learned(host):
    LEARNED.pop(host, None); _save_learned()

def clear_learned():
    LEARNED.clear(); _save_learned()

# ── Persistence (used by the control UI) ─────────────────────────────────────────

def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)

def save_rules(rules):
    _atomic_write(RULES_PATH, json.dumps({"rules": rules}, indent=2))
    reload_config()

def save_keywords(keywords):
    _atomic_write(KEYWORDS_PATH, "\n".join(keywords) + "\n")
    reload_config()

def save_config(patch):
    global CONFIG
    CONFIG = {**CONFIG, **patch}
    _atomic_write(CONFIG_PATH, json.dumps(CONFIG, indent=2))
    try:
        os.chmod(CONFIG_PATH, 0o600)      # root-only: keep the password hash unreadable by other users
    except OSError:
        pass
    reload_config()

# ── Export / import (replicate config to another machine) ─────────────────────────

def export_config():
    """Portable settings — excludes the password and machine-local runtime state."""
    return {
        "version": 1,
        "rules": RULES,
        "keywords": KEYWORDS,
        "bypass": bypass_entries(),
        "settings": {
            "threshold": threshold(),
            "safeSearch": safe_search_enabled(),
            "categories": CONFIG.get("categories") or {},
        },
    }

def import_config(data):
    if not isinstance(data, dict):
        return
    if isinstance(data.get("rules"), list):
        save_rules([{"type": "allow" if r.get("type") == "allow" else "block",
                     "pattern": (r.get("pattern") or "").strip()}
                    for r in data["rules"] if isinstance(r, dict) and (r.get("pattern") or "").strip()])
    if isinstance(data.get("keywords"), list):
        seen = []
        for k in data["keywords"]:
            k = (k or "").strip().lower()
            if len(k) >= 2 and k not in seen:
                seen.append(k)
        save_keywords(seen)
    patch = {}
    if isinstance(data.get("bypass"), list):
        patch["bypass"] = [{"pattern": (e.get("pattern") if isinstance(e, dict) else e or "").strip().lower(),
                            "group": (e.get("group") if isinstance(e, dict) else "") or ""}
                           for e in data["bypass"]
                           if (isinstance(e, dict) and e.get("pattern")) or isinstance(e, str)]
    s = data.get("settings") or {}
    if "threshold" in s:
        patch["threshold"] = max(0, min(100, int(s["threshold"])))
    if "safeSearch" in s:
        patch["safeSearch"] = bool(s["safeSearch"])
    if isinstance(s.get("categories"), dict):
        patch["categories"] = {k: bool(v) for k, v in s["categories"].items()}
    if patch:
        save_config(patch)

# ── Password (PBKDF2-SHA256) ─────────────────────────────────────────────────────

PBKDF2_ITER = 600000            # current guidance; legacy hashes (100k) upgrade on next login

def _hash(pw, salt, iters):
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)).decode()

def has_password():
    return bool(CONFIG.get("passwordHash"))

def set_password(pw):
    salt = secrets.token_bytes(16)
    save_config({"passwordHash": _hash(pw, salt, PBKDF2_ITER),
                 "passwordSalt": base64.b64encode(salt).decode(),
                 "passwordIter": PBKDF2_ITER})

def verify_password(pw):
    if not CONFIG.get("passwordHash") or not CONFIG.get("passwordSalt"):
        return False
    salt = base64.b64decode(CONFIG["passwordSalt"])
    iters = int(CONFIG.get("passwordIter") or 100000)     # legacy hashes were 100k
    ok = hmac.compare_digest(_hash(pw, salt, iters), CONFIG["passwordHash"])
    if ok and iters < PBKDF2_ITER:
        set_password(pw)                                   # transparently upgrade the hash
    return ok

# ── Search-query extraction ──────────────────────────────────────────────────────

_SEARCH_ENGINES = [
    (lambda h, u: bool(re.search(r"(^|\.)google\.[a-z.]+$", h)) and u.path.startswith("/search"), "q"),
    (lambda h, u: bool(re.search(r"(^|\.)bing\.com$", h)) and u.path.startswith("/search"), "q"),
    (lambda h, u: bool(re.search(r"(^|\.)duckduckgo\.com$", h)) and "q" in parse_qs(u.query), "q"),
    (lambda h, u: bool(re.search(r"(^|\.)youtube\.com$", h)) and u.path.startswith("/results"), "search_query"),
    (lambda h, u: bool(re.search(r"(^|\.)yahoo\.com$", h)) and "/search" in u.path, "p"),
]

def search_query(url):
    """Return the search terms if this URL is a search-engine query, else None."""
    u = urlparse(url)
    host = (u.hostname or "").lower()
    q = parse_qs(u.query)
    for match, param in _SEARCH_ENGINES:
        if match(host, u):
            v = (q.get(param) or [""])[0].strip()
            if v:
                return v
    return None

# ── Activity log (all traffic; rotating file + 30-day UI view) ───────────────────

ACTIVITY_LOG = os.path.join(CONFIG_DIR, "activity.log")
ACTIVITY_MAX_BYTES = 100 * 1024 * 1024      # rotate at 100 MB
ACTIVITY_BACKUPS = 30                        # keep up to 30 rotated files
RETAIN_DAYS = 30

def _log_files_newest_first():
    files = [ACTIVITY_LOG] if os.path.exists(ACTIVITY_LOG) else []
    for i in range(1, ACTIVITY_BACKUPS + 1):
        p = "%s.%d" % (ACTIVITY_LOG, i)
        if os.path.exists(p):
            files.append(p)
    return files

def _tail(path, n):
    """Return up to the last n lines of a file (in file order) without loading it all."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            pos = f.tell()
            data = b""
            while pos > 0 and data.count(b"\n") <= n:
                read = min(65536, pos)
                pos -= read
                f.seek(pos)
                data = f.read(read) + data
            return data.decode("utf-8", "replace").splitlines()[-n:]
    except OSError:
        return []

def read_activity(limit=500, days=RETAIN_DAYS, q="", kind="activity", max_scan=40000):
    """Recent activity, newest first, filtered. kind: activity|searches|blocked|all."""
    import datetime
    cutoff = datetime.datetime.now().timestamp() - days * 86400
    ql = (q or "").lower().strip()
    out, scanned = [], 0
    for path in _log_files_newest_first():
        budget = max_scan - scanned
        if budget <= 0:
            break
        for line in reversed(_tail(path, budget)):
            scanned += 1
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            try:
                ts = datetime.datetime.fromisoformat(rec.get("t", "")).timestamp()
            except ValueError:
                ts = None
            if ts is not None and ts < cutoff:
                return out                     # entries are chronological → we're done
            if kind == "searches" and not rec.get("query"):
                continue
            if kind == "blocked" and rec.get("action") != "blocked":
                continue
            if kind == "activity" and not (rec.get("query") or rec.get("dest") == "document"
                                           or rec.get("action") == "blocked"):
                continue
            if ql and ql not in (rec.get("url", "") + " " + rec.get("query", "") + " " + rec.get("host", "")).lower():
                continue
            out.append(rec)
            if len(out) >= limit:
                return out
    return out

def clear_activity():
    """Wipe the activity log. Truncates the current file (the proxy writes in append mode,
    so its open handle keeps working from EOF=0) and removes rotated backups."""
    try:
        open(ACTIVITY_LOG, "w").close()
    except OSError:
        pass
    for i in range(1, ACTIVITY_BACKUPS + 1):
        p = "%s.%d" % (ACTIVITY_LOG, i)
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass

def prune_old_logs():
    """Delete rotated activity files older than RETAIN_DAYS (size rotation + time cap)."""
    import time as _t
    cutoff = _t.time() - RETAIN_DAYS * 86400
    for i in range(1, ACTIVITY_BACKUPS + 1):
        p = "%s.%d" % (ACTIVITY_LOG, i)
        try:
            if os.path.exists(p) and os.path.getmtime(p) < cutoff:
                os.remove(p)
        except OSError:
            pass

# ── "Monitored" banner (injected into pages by the proxy) ────────────────────────
# Minimised to a small pill (bottom-right) by default; click to expand. Built entirely
# in a closed shadow root with styles set via JS (no <style>/inline attrs) so it needs
# only a script nonce to satisfy CSP, and re-injects itself if removed.

BANNER_JS = (
    "(function(){var ID='__wf_monitor__',MK='__wf_min__';"
    "function ap(b,p,c){b.style.display=c?'none':'flex';p.style.display=c?'block':'none';}"
    "function mk(){if(document.getElementById(ID)||!document.body)return;"
    "var h=document.createElement('div');h.id=ID;var s=h.attachShadow({mode:'closed'});"
    "var b=document.createElement('div');"
    "b.style.cssText=\"position:fixed;bottom:0;left:0;right:0;z-index:2147483647;background:#b91c1c;color:#fff;"
    "font:13px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:7px 14px;display:flex;"
    "align-items:center;justify-content:space-between;gap:12px;box-shadow:0 -2px 8px rgba(0,0,0,.35)\";"
    "var m=document.createElement('span');m.textContent='\\uD83D\\uDD12 This browsing session is monitored.';m.style.cssText='flex:1';"
    "var mb=document.createElement('button');mb.textContent='Minimise';"
    "mb.style.cssText=\"background:transparent;border:1px solid rgba(255,255,255,.35);color:#fff;padding:2px 10px;"
    "border-radius:4px;cursor:pointer;font-size:11px;white-space:nowrap\";"
    "b.appendChild(m);b.appendChild(mb);var p=document.createElement('div');"
    "p.textContent='\\uD83D\\uDD12 Monitored';"
    "p.style.cssText=\"position:fixed;bottom:10px;right:10px;z-index:2147483647;background:#b91c1c;color:#fff;"
    "font:11px -apple-system,sans-serif;padding:4px 10px;border-radius:14px;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,.4)\";"
    "s.appendChild(b);s.appendChild(p);var c=sessionStorage.getItem(MK)!=='0';ap(b,p,c);"
    "mb.addEventListener('click',function(){sessionStorage.setItem(MK,'1');ap(b,p,true);});"
    "p.addEventListener('click',function(){sessionStorage.setItem(MK,'0');ap(b,p,false);});"
    "(document.body||document.documentElement).appendChild(h);}"
    "mk();new MutationObserver(function(){if(!document.getElementById(ID))mk();})"
    ".observe(document.documentElement,{childList:true,subtree:true});})();"
)

def banner_snippet(nonce):
    return '<script nonce="%s">%s</script>' % (nonce, BANNER_JS)

def csp_with_nonce(csp, nonce):
    """Allow our nonce'd banner script under an existing CSP."""
    add = "'nonce-%s'" % nonce
    order, directives = [], {}
    for part in [p.strip() for p in csp.split(";") if p.strip()]:
        name = part.split()[0].lower()
        directives[name] = part
        order.append(name)
    if "script-src" in directives:
        directives["script-src"] += " " + add
    elif "default-src" in directives:
        directives["default-src"] += " " + add
    else:
        return csp
    return "; ".join(directives[n] for n in order)

# ── Blocked page ─────────────────────────────────────────────────────────────────

def blocked_page(reason, url):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Blocked</title><style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#fff;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:40px 48px;max-width:520px;text-align:center;
box-shadow:0 20px 60px rgba(0,0,0,.4)}}
.icon{{font-size:52px}} h1{{margin:12px 0 8px;font-size:22px}}
.muted{{color:#94a3b8;font-size:13px;word-break:break-all}} .reason{{color:#f87171;font-weight:600;margin-top:12px}}
</style></head><body><div class="card"><div class="icon">🛡️</div>
<h1>This site is blocked</h1>
<p class="muted">{url}</p>
<p class="reason">{reason}</p>
<p class="muted">Blocked by Family Web Filter.</p></div></body></html>"""

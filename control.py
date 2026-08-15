"""Web Filter — local control UI (Flask). Password-protected; binds to 127.0.0.1.

Run with:  python3 control.py   (or via the LaunchDaemon the installer sets up)
Serves ui/ and a small JSON API that reads/writes config/. The proxy hot-reloads the
files, so changes here apply live.
"""
import os
import re
import io
import csv
import json
import time
import functools
import secrets
import subprocess

from flask import Flask, request, session, jsonify, send_from_directory, Response

import filterlib as F
import categorize as C

HERE = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(HERE, "ui")
SECRET_PATH = os.path.join(HERE, "config", ".secret")
PORT = 8788
IDLE_TIMEOUT = 60           # seconds of inactivity before the session auto-locks


def _secret():
    try:
        with open(SECRET_PATH, "rb") as f:
            return f.read()
    except OSError:
        s = secrets.token_bytes(32)
        try:
            with open(SECRET_PATH, "wb") as f:
                f.write(s)
            os.chmod(SECRET_PATH, 0o600)
        except OSError:
            pass
        return s


app = Flask(__name__, static_folder=None)
app.secret_key = _secret()


def authed():
    return bool(session.get("auth")) or not F.has_password()   # first run is open until a pw is set


def require(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        F.reload_config()
        F.reload_learned()      # learned.json is written by the proxy process; stay fresh
        if not authed():
            return jsonify(ok=False, error="Locked"), 401
        return fn(*a, **k)
    return wrapper


@app.before_request
def _idle_guard():
    """Enforce the idle timeout server-side so it can't be bypassed by disabling JS.
    Any non-GET request (a user action or the client heartbeat) counts as activity and
    refreshes the clock; a session left idle past the timeout is cleared -> locked."""
    if session.get("auth"):
        now = time.time()
        if now - session.get("last", now) > IDLE_TIMEOUT:
            session.clear()
        elif request.method != "GET":
            session["last"] = now


# ── static UI ────────────────────────────────────────────────────────────────────
@app.get("/")
def index():
    return send_from_directory(UI_DIR, "index.html")

@app.get("/<path:p>")
def static_files(p):
    return send_from_directory(UI_DIR, p)


# ── auth + state ─────────────────────────────────────────────────────────────────
@app.post("/api/login")
def login():
    if F.verify_password((request.json or {}).get("password", "")):
        session["auth"] = True
        session["last"] = time.time()
        return jsonify(ok=True)
    return jsonify(ok=False, error="Incorrect password"), 401

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.post("/api/heartbeat")
@require
def heartbeat():
    # The before_request hook refreshes the idle clock for this (non-GET) request; this
    # just tells the client the session is still valid (or returns 401 once it's locked).
    return jsonify(ok=True)

@app.get("/api/state")
def state():
    F.reload_config()
    F.reload_learned()
    cats = [{"id": c["id"], "label": c["label"], "enabled": F.category_enabled(c["id"])}
            for c in C.CATEGORIES]
    return jsonify(ok=True, hasPassword=F.has_password(), authed=authed(),
                   threshold=F.threshold(), safeSearch=F.safe_search_enabled(),
                   banner=F.banner_enabled(), bypassAll=F.bypass_all(),
                   proxyUp=F.proxy_listening(), failOpen=F.is_failopen(), categories=cats,
                   ruleCount=len(F.RULES), keywordCount=len(F.KEYWORDS), learnedCount=len(F.LEARNED))

# ── export / import config ───────────────────────────────────────────────────────
@app.get("/api/export")
@require
def export_cfg():
    return Response(json.dumps(F.export_config(), indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=webfilter-config.json"})

@app.post("/api/import")
@require
def import_cfg():
    data = request.json or {}
    if F.has_password() and not F.verify_password(data.get("password", "")):
        return jsonify(ok=False, error="Incorrect password"), 401
    F.import_config(data.get("config") or {})
    return jsonify(ok=True)


@app.post("/api/password")
def password():
    data = request.json or {}
    if F.has_password() and not session.get("auth") and not F.verify_password(data.get("current", "")):
        return jsonify(ok=False, error="Current password incorrect"), 401
    nxt = data.get("next", "")
    if len(nxt) < 4:
        return jsonify(ok=False, error="Password must be at least 4 characters"), 400
    F.set_password(nxt)
    session["auth"] = True
    session["last"] = time.time()
    return jsonify(ok=True)


# ── rules ────────────────────────────────────────────────────────────────────────
@app.get("/api/rules")
@require
def get_rules():
    return jsonify(ok=True, rules=F.RULES)

@app.put("/api/rules")
@require
def put_rules():
    rules = (request.json or {}).get("rules", [])
    clean = [{"type": "allow" if r.get("type") == "allow" else "block",
              "pattern": (r.get("pattern") or "").strip()}
             for r in rules if (r.get("pattern") or "").strip()]
    F.save_rules(clean)
    return jsonify(ok=True, rules=F.RULES)


# ── keywords ─────────────────────────────────────────────────────────────────────
@app.get("/api/keywords")
@require
def get_keywords():
    return jsonify(ok=True, keywords=F.KEYWORDS)

@app.put("/api/keywords")
@require
def put_keywords():
    raw = (request.json or {}).get("keywords", [])
    if isinstance(raw, str):
        raw = re.split(r"[\n,;]+", raw)
    seen = []
    for k in raw or []:
        k = (k or "").strip().lower()
        if len(k) >= 2 and k not in seen:
            seen.append(k)
    F.save_keywords(seen)
    return jsonify(ok=True, keywords=F.KEYWORDS)


# ── config (threshold / safesearch / categories) ─────────────────────────────────
@app.patch("/api/config")
@require
def patch_config():
    data = request.json or {}
    patch = {}
    if "threshold" in data:
        patch["threshold"] = max(0, min(100, int(data["threshold"])))
    if "safeSearch" in data:
        patch["safeSearch"] = bool(data["safeSearch"])
    if "banner" in data:
        patch["banner"] = bool(data["banner"])
    if "categories" in data:
        cats = dict(F.CONFIG.get("categories") or {})
        for k, v in (data["categories"] or {}).items():
            cats[k] = bool(v)
        patch["categories"] = cats
    if patch:
        F.save_config(patch)
    return jsonify(ok=True)


# ── learned domains ──────────────────────────────────────────────────────────────
@app.get("/api/learned")
@require
def get_learned():
    return jsonify(ok=True, learned=list(F.LEARNED.values()))

@app.delete("/api/learned/<host>")
@require
def del_learned(host):
    F.delete_learned(host)
    return jsonify(ok=True)

@app.post("/api/learned/clear")
@require
def clear_learned_all():
    if F.has_password() and not F.verify_password((request.json or {}).get("password", "")):
        return jsonify(ok=False, error="Incorrect password"), 401
    F.clear_learned()
    return jsonify(ok=True)

@app.post("/api/learned/<host>/promote")
@require
def promote_learned(host):
    rec = F.LEARNED.get(host)
    if rec:
        F.save_rules(list(F.RULES) + [{"type": "block", "pattern": host}])
        F.delete_learned(host)
    return jsonify(ok=True)


# ── bypass (no-intercept passthrough) ────────────────────────────────────────────
@app.get("/api/bypass")
@require
def get_bypass():
    return jsonify(ok=True, bypass=F.bypass_entries())

@app.put("/api/bypass")
@require
def put_bypass():
    raw = (request.json or {}).get("bypass", [])
    seen, out = set(), []
    for e in raw or []:
        if isinstance(e, str):
            e = {"pattern": e, "group": ""}
        p = (e.get("pattern") or "").strip().lower()
        g = (e.get("group") or "").strip()
        if p and p not in seen:
            seen.add(p); out.append({"pattern": p, "group": g})
    F.save_config({"bypass": out})
    return jsonify(ok=True, bypass=F.bypass_entries())


# ── bypass bundles (presets) ─────────────────────────────────────────────────────
@app.get("/api/bundles")
@require
def get_bundles():
    return jsonify(ok=True, bundles=[{"name": n, "domains": d} for n, d in F.bundles().items()])

@app.post("/api/bundles/<name>/add")
@require
def add_bundle(name):
    domains = F.bundles().get(name)
    if not domains:
        return jsonify(ok=False, error="Unknown bundle"), 404
    existing = {e["pattern"] for e in F.bypass_entries()}
    merged = F.bypass_entries() + [{"pattern": d, "group": name} for d in domains if d not in existing]
    F.save_config({"bypass": merged})
    return jsonify(ok=True, bypass=F.bypass_entries())


# ── suggested related domains ────────────────────────────────────────────────────
@app.get("/api/suggestions")
@require
def get_suggestions():
    return jsonify(ok=True, suggestions=F.list_suggestions())

@app.post("/api/suggestions/<domain>/add")
@require
def add_suggestion_to_bypass(domain):
    domain = domain.strip().lower()
    group = ""
    for s in F.list_suggestions():                       # inherit the parent site's group
        if s.get("domain") == domain:
            for parent in s.get("parents", []):
                group = F.group_for_host(parent)
                if group:
                    break
            break
    if domain not in {e["pattern"] for e in F.bypass_entries()}:
        F.save_config({"bypass": F.bypass_entries() + [{"pattern": domain, "group": group}]})
    F.dismiss_suggestion(domain)
    return jsonify(ok=True, bypass=F.bypass_entries())

@app.delete("/api/suggestions/<domain>")
@require
def dismiss_suggestion(domain):
    F.dismiss_suggestion(domain)
    return jsonify(ok=True)


# ── activity log ─────────────────────────────────────────────────────────────────
@app.get("/api/log")
@require
def get_log():
    per_page = max(10, min(500, int(request.args.get("per_page", 50))))
    page = max(0, int(request.args.get("page", 0)))
    days = max(1, min(90, int(request.args.get("days", F.RETAIN_DAYS))))
    kind = request.args.get("kind", "activity")   # activity | searches | blocked | all
    q = request.args.get("q", "")
    want = (page + 1) * per_page + 1               # one extra to detect a next page
    matches = F.read_activity(limit=want, days=days, q=q, kind=kind, max_scan=max(40000, want * 3))
    start = page * per_page
    return jsonify(ok=True, log=matches[start:start + per_page],
                   page=page, perPage=per_page, hasMore=len(matches) > start + per_page)

@app.get("/api/log.csv")
@require
def log_csv():
    days = max(1, min(90, int(request.args.get("days", F.RETAIN_DAYS))))
    kind = request.args.get("kind", "activity")
    q = request.args.get("q", "")
    rows = F.read_activity(limit=100000, days=days, q=q, kind=kind, max_scan=300000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "action", "reason", "query", "host", "url", "dest"])
    for e in rows:
        w.writerow([e.get("t", ""), e.get("action", ""), e.get("reason", ""), e.get("query", ""),
                    e.get("host", ""), e.get("url", ""), e.get("dest", "")])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=activity.csv"})

@app.post("/api/bypassall")
@require
def set_bypassall():
    data = request.json or {}
    enabled = bool(data.get("enabled"))
    # Enabling disables all protection -> require the password. Disabling re-enables
    # filtering (safer), so no password needed.
    if enabled and F.has_password() and not F.verify_password(data.get("password", "")):
        return jsonify(ok=False, error="Incorrect password"), 401
    F.save_config({"bypassAll": enabled})
    return jsonify(ok=True)


# ── health / diagnostics ─────────────────────────────────────────────────────────
@app.get("/api/health")
@require
def health():
    log = ""
    try:
        with open(os.path.join(HERE, "config", "health.log"), encoding="utf-8") as f:
            log = f.read()[-8000:]
    except OSError:
        pass
    return jsonify(ok=True, proxyUp=F.proxy_listening(), failOpen=F.is_failopen(), log=log)

@app.post("/api/health/run")
@require
def health_run():
    try:
        out = subprocess.run(["/bin/bash", os.path.join(HERE, "doctor.sh")],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception as e:
        out = "Failed to run health check: %s" % e
    return jsonify(ok=True, output=out)


@app.post("/api/log/clear")
@require
def clear_log():
    if F.has_password() and not F.verify_password((request.json or {}).get("password", "")):
        return jsonify(ok=False, error="Incorrect password"), 401
    F.clear_activity()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)

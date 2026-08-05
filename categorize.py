"""On-device content categorizer — Python port of the extension's categorize.js.
Extracts signals from raw HTML (the proxy sees the decrypted body) and scores them into
categories. Same lexicons, weights and caps as the extension."""
import re

CATEGORIES = [
    {"id": "games", "label": "Games", "structural": True,
     "strong": ["play now", "play free", "free games", "free online games", "online games",
                "play online", "high score", "game over", "new games", "top games",
                "unblocked games", "html5 games", "arcade games", "io games", "multiplayer game"],
     "weak": ["game", "games", "play", "player", "level", "levels", "arcade", "puzzle",
              "puzzles", "multiplayer", "leaderboard", "gameplay", "coins", "gaming"],
     "engines": ["unity", "unityweb", "phaser", "pixi.js", "pixijs", "cocos", "cocos2d",
                 "createjs", "melonjs", "babylon", "playcanvas", "godot", "gdevelop",
                 "construct", "c2runtime", "c3runtime", "ruffle", "kaboom", "gamemaker",
                 "html5games", "game.min.js", "gameloop"],
     "embed_hosts": ["itch.zone", "html5.gamedistribution.com", "gamedistribution.com",
                     "poki-gdl.com", "cdn.htmlgames.com"]},
    {"id": "adult", "label": "Adult / explicit",
     "strong": ["porn", "pornography", "porn videos", "sex videos", "adult videos",
                "xxx videos", "free porn", "live sex", "sex cam", "sex chat", "camgirl",
                "nude photos", "explicit content", "18+ only", "adults only", "nsfw content",
                "escort service"],
     "weak": ["porn", "xxx", "nude", "nudes", "sex", "erotic", "hentai", "onlyfans",
              "camgirls", "fetish", "hardcore", "nsfw", "escort"]},
    {"id": "gambling", "label": "Gambling",
     "strong": ["online casino", "live casino", "sports betting", "sportsbook", "place your bet",
                "poker room", "online poker", "free spins", "slot machine", "betting odds",
                "deposit bonus", "welcome bonus", "real money", "online slots", "bet now"],
     "weak": ["casino", "betting", "bet", "bets", "poker", "slots", "roulette", "blackjack",
              "baccarat", "wager", "jackpot", "lottery", "gamble", "gambling", "odds", "payout"]},
    {"id": "violence", "label": "Violence / gore",
     "strong": ["graphic violence", "gore videos", "extreme violence", "real gore",
                "beheading video", "execution video", "brutal death", "shocking death"],
     "weak": ["gore", "gory", "beheading", "decapitation", "mutilation", "massacre",
              "torture", "brutal", "bloodbath", "snuff"]},
    {"id": "drugs", "label": "Drugs & alcohol",
     "strong": ["buy weed online", "buy cannabis online", "order marijuana", "how to get high",
                "buy cocaine", "buy alcohol online", "vape shop", "buy vapes online", "thc edibles"],
     "weak": ["marijuana", "cannabis", "weed", "cocaine", "heroin", "meth", "mdma",
              "psychedelics", "edibles", "bong", "vape", "vaping", "e-cigarette"]},
    {"id": "weapons", "label": "Weapons",
     "strong": ["guns for sale", "buy guns online", "firearms for sale", "buy ammunition",
                "ammo for sale", "ghost gun", "build a gun", "handguns for sale", "rifles for sale"],
     "weak": ["firearm", "firearms", "handgun", "ammunition", "ammo", "ar-15", "assault rifle",
              "silencer", "magazine capacity"]},
    {"id": "dating", "label": "Dating / hookups",
     "strong": ["online dating", "find a date", "meet singles", "hookup tonight", "adult dating",
                "local singles", "meet women near you", "meet men near you", "find a hookup"],
     "weak": ["dating", "singles", "hookup", "hookups", "flirt", "sugar daddy", "sugar baby"]},
    {"id": "piracy", "label": "Piracy / illegal streams",
     "strong": ["watch free movies online", "free movie download", "download full movie",
                "stream free movies", "torrent download", "free tv shows online", "crack download"],
     "weak": ["torrent", "torrents", "pirate", "pirated", "warez", "keygen", "cracked",
              "putlocker", "123movies", "fmovies", "yify"]},
    {"id": "social", "label": "Social media",
     "strong": ["log in to facebook", "sign up for tiktok", "create your account and connect"],
     "weak": ["newsfeed", "news feed", "followers", "following", "stories", "reels",
              "direct message", "timeline", "retweet"]},
]

CAP = {"engine": 30, "embed": 30, "canvas": 12, "strong_meta": 36,
       "weak_meta": 24, "strong_body": 18, "weak_body": 18}

# ── Signal extraction from raw HTML ──────────────────────────────────────────────

def _meta(html, name):
    m = re.search(r'<meta\b[^>]*\b(?:name|property)=["\'](?:og:)?' + name +
                  r'["\'][^>]*\bcontent=["\'](.*?)["\']', html, re.I | re.S)
    if not m:
        m = re.search(r'<meta\b[^>]*\bcontent=["\'](.*?)["\'][^>]*\b(?:name|property)=["\'](?:og:)?' +
                      name + r'["\']', html, re.I | re.S)
    return m.group(1) if m else ""

def _strip_tags(html):
    html = re.sub(r'<(script|style)\b[^>]*>.*?</\1>', ' ', html, flags=re.I | re.S)
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html)).strip()

def extract_signals(html, url=""):
    title = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    headings = re.findall(r'<h[12][^>]*>(.*?)</h[12]>', html, re.I | re.S)[:20]
    return {
        "url": url,
        "title": title.group(1) if title else "",
        "metaDescription": _meta(html, "description"),
        "metaKeywords": _meta(html, "keywords"),
        "headings": " | ".join(re.sub(r'<[^>]+>', '', h).strip() for h in headings),
        "textSample": _strip_tags(html)[:4000],
        "canvasCount": len(re.findall(r'<canvas\b', html, re.I)),
        "scriptSrcs": [s.lower() for s in re.findall(r'<script\b[^>]+src=["\'](.*?)["\']', html, re.I)][:100],
        "iframeSrcs": [s.lower() for s in re.findall(r'<iframe\b[^>]+src=["\'](.*?)["\']', html, re.I)][:100],
    }

# ── Scoring (mirrors categorize.js) ──────────────────────────────────────────────

def _count_distinct(hay, needles):
    return sum(1 for w in needles if w in hay)

def _score_category(cat, sig, meta, body, srcs):
    score = 0
    reasons = []
    if cat.get("structural"):
        eng = next((t for t in cat.get("engines", []) if any(t in s for s in srcs)), None)
        if eng:
            score += CAP["engine"]; reasons.append("engine: " + eng)
        emb = next((h for h in cat.get("embed_hosts", []) if any(h in s for s in sig["iframeSrcs"])), None)
        if emb:
            score += CAP["embed"]; reasons.append("embed: " + emb)
        if sig["canvasCount"] > 0:
            score += CAP["canvas"]; reasons.append("canvas x%d" % sig["canvasCount"])
    strong_meta = [p for p in cat["strong"] if p in meta]
    if strong_meta:
        score += min(CAP["strong_meta"], len(strong_meta) * 12)
        reasons.append("title/meta: " + ", ".join(strong_meta[:3]))
    wm = _count_distinct(meta, cat["weak"])
    if wm:
        score += min(CAP["weak_meta"], wm * 6)
    strong_body = [p for p in cat["strong"] if p in body]
    if strong_body:
        score += min(CAP["strong_body"], len(strong_body) * 6)
    if body:
        freq = 0
        for w in cat["weak"]:
            freq += len(re.findall(r'\b' + re.escape(w) + r'\b', body))
        if freq:
            score += min(CAP["weak_body"], round(freq / 2))
    return {"category": cat["id"], "label": cat["label"], "score": min(100, score), "reasons": reasons}

def score_signals(sig):
    meta = " \n ".join(x for x in [sig.get("title"), sig.get("metaDescription"),
                                   sig.get("metaKeywords"), sig.get("headings")] if x).lower()
    body = (sig.get("textSample") or "").lower()
    srcs = (sig.get("scriptSrcs") or []) + (sig.get("iframeSrcs") or [])
    ranked = [_score_category(c, sig, meta, body, srcs) for c in CATEGORIES]
    return sorted([r for r in ranked if r["score"] > 0], key=lambda r: r["score"], reverse=True)

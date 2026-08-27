# Family Web Filter — proxy edition

A system-wide filtering **proxy** with a local **control UI**. It enforces URL rules,
keyword matching (URL + page content), category scoring, and SafeSearch across **every
browser and app**, with a real blocked page. Runs **unsigned** (no Apple Developer
account): it's just Python processes managed by LaunchDaemons.

## Install (macOS)

```bash
git clone https://github.com/reddoubledecker/webfilter-proxy.git
sudo cp -R webfilter-proxy /usr/local/webfilter-proxy   # install outside the user home so root can read it
cd /usr/local/webfilter-proxy
sudo ./install.sh    # venv+deps, trusts CA, installs daemons, sets the proxy, opens the QUIC profile
```

`install.sh` also **opens the Chrome QUIC-disable profile** at the end — **approve it** in
System Settings → General → Device Management (Profiles). This is required: without it,
Chrome uses HTTP-3/QUIC and bypasses the proxy for Google/YouTube. (macOS can't install a
profile silently, so this one click is unavoidable.) Then **fully quit and reopen Chrome**.

> A pf-based QUIC block (`block-quic.sh`) does **not** work on macOS — Chrome's QUIC packets
> don't hit the filter — so the Chrome profile is the real fix.

Then open the **control UI** and set a password:

> **http://127.0.0.1:8788**

Filtering is live for all browsers. Remove with `sudo ./uninstall.sh` (then remove the QUIC
profile in System Settings if you want QUIC back).

## Updating

The running copy lives at `/usr/local/webfilter-proxy` (outside the user home folder, which
macOS blocks root services from reading). After editing the source, deploy in one step:

```bash
sudo ./deploy.sh        # rsync code to /usr/local + restart both daemons
```

`deploy.sh` syncs **code + UI only** — it never overwrites `config/` (your live rules,
keywords, password, learned domains, logs), the venv, or the CA.

## Manage everything in the UI
Password-protected, at `http://127.0.0.1:8788`. A left **sidebar** groups everything into
**Dashboard · Filtering · Bypass · Activity · Diagnostics · Settings** — one area on screen at
a time, no long scroll. **Dark mode** toggle in the header. The session **auto-locks after 1
minute idle** and on closing the page (re-enter the password to return).

- **Dashboard** — at-a-glance status and summary, not a feed: filter state, **Blocked /
  Requests / Searches (last 24h)**, **Top blocked sites** and **top block reasons** (last 7
  days), and a one-line inventory (rules / keywords / categories on / bypassed / auto-detected).
- **Filtering** (sub-tabs):
  - *Detection* — Safe Search toggle, **"monitored" banner** toggle, sensitivity, per-category
    checklist. The banner is injected by the proxy into every page (minimised to a small pill,
    bottom-right; click to expand). A **⚠️ Bypass all (testing)** switch flips mitmproxy to
    **no-intercept for all traffic** (nothing decrypted, filtered, or logged — real certs
    everywhere); a prominent orange banner shows while it's on.
  - *URL rules* — add/delete block & allow (most-specific-wins); **sortable by pattern**.
  - *Keywords* — add/remove (98 defaults preloaded); **hidden by default** (click *Show*) since
    keywords can be sensitive.
  - *Detected* — auto-detected domains; promote to a rule or delete (Clear all re-prompts for
    the password).
- **Bypass** — sites/domain-keywords/wildcards passed through untouched (not decrypted,
  filtered, or logged) for cert-pinned sites/apps that break under the MITM. Entries are
  **grouped by name** (e.g. a *Netflix* group holding `netflix.com`, `nflxvideo.net`, …).
  One-click **preset bundles** add a service's domains, and **Suggested related domains** shows
  what your bypassed sites pulled content from so you can add them (inheriting the parent's group).
- **Activity** — **all** traffic (allowed + blocked), with **search terms** captured
  (Google/Bing/DuckDuckGo/YouTube). Filter by Pages &amp; searches / Searches / Blocked /
  Everything, plus text search, pagination (50/page), **CSV export**, and **Clear log**
  (re-enter the password to wipe it). Last 30 days shown.
- **Diagnostics** — run the health check in-browser and read the latest diagnosis (see below).
- **Settings** — **Emergency bypass** (see below), **Backup / transfer** (export/import your
  config — rules, keywords, categories, Safe Search, bypass; password *not* included), and
  **Change password**.

Changes apply **live** — the proxy hot-reloads `config/` (no restart needed).

## How it works
```
 Browser / apps ──proxy──▶ [ mitmdump -s filter.py @ 127.0.0.1:8080 ] ──▶ Internet
   control UI  ◀── reads/writes ── config/ ──▶ hot-reloaded by the proxy
   (Flask @ 127.0.0.1:8788, LaunchDaemon)
```
- `filter.py` — mitmproxy addon: request/response filtering.
- `filterlib.py` — engine (rules, keywords, SafeSearch, learned, password), hot-reload.
- `categorize.py` — category scorer (runs on decrypted HTML).
- `control.py` + `ui/` — the Flask control server and web UI.
- `config/` — `rules.json`, `keywords.txt`, `config.json`, `learned.json`, and the
  **activity log** `activity.log` (JSON-lines; **rotates at 100 MB**, up to 30 backups,
  pruned after 30 days).

Two LaunchDaemons (root, auto-restart) run the proxy and the UI. The `mitmproxy` CA is
generated into `mitm-ca/` and trusted in the System keychain so HTTPS can be inspected.

## Tamper model
- Proxy + UI run as **root LaunchDaemons** → a Standard (non-admin) child can't stop them.
- System proxy + CA trust are system-level → need admin to change.
- Pair with a **Standard child account + Screen Time** (lock network/System Settings) so the
  proxy can't be unset. The config files are root-owned, so only the UI (password) edits them.

## Multi-user & per-device rollout

**Scope of each piece:**
- The **proxy** (system proxy + CA + root daemons) is **whole-machine** — it filters *every*
  macOS user and *every* Chrome profile, in **normal and incognito** windows (incognito is
  logged too; it can't escape a system proxy). Note it filters **you** as well: macOS proxy
  is per-network-service, not per-user, so you can't have "kid filtered, parent free" on one
  Mac. You hold the password to pause/allow/bypass.
- The **QUIC policy** (`chrome-disable-quic.mobileconfig`) is **System-scoped**, so one admin
  approval covers all users' Chrome.

**Per Mac:**
1. `sudo ./install.sh` — installs the proxy and opens the QUIC profile → **approve it** (it
   installs at System scope for all users).
2. Fully quit and reopen Chrome.
3. Give each child a **Standard (non-admin) account**; keep the admin password private. A
   Standard user can't stop the daemons, change the proxy, remove the profile, or edit the
   root-owned `config/`.
4. Turn on **Screen Time** (with a passcode) for the child: block other browsers, and lock
   Network / System Settings so the proxy can't be unset.

**Replicate settings across Macs:** in the UI, **Export** your config and **Import** it on the
next machine (rules, keywords, categories, Safe Search, bypass — the password is not included).

## Resilience & self-repair

A dead proxy with the system proxy still set = no internet, so the service is built to
heal itself:
- **Watchdog daemon** (`watchdog.sh`, runs every 60s): checks the proxy is actually
  listening (as root, no false negatives), restarts it if it's down, and keeps the control
  UI up too.
- **Fail-open after 3 minutes**: if the proxy can't be revived within ~3 min, the watchdog
  **restores unfiltered internet** and posts a desktop alert — so a crash never bricks the
  Mac — then **re-locks automatically** the moment the proxy recovers.
- **Hardened daemons**: `KeepAlive` + `ThrottleInterval` so launchd restarts on crash.
- **Defensive proxy**: a filtering bug fails open *per request* instead of breaking the page,
  and the background task shuts down cleanly.
- **Status in the UI**: the header shows 🟢/🔴 filter status, and a red banner appears while
  fail-open is active. `chrome://policy`-style transparency instead of a silent outage.
- **CA maintenance**: `sudo ./regenerate-ca.sh` rebuilds the mitmproxy CA with a fresh serial
  (fixes the `non-positive serial number` deprecation before a future `cryptography` upgrade
  turns it into a hard crash) and re-trusts it.

## Emergency bypass (kill switch)

If the filter breaks and you just need browsing to work, restore unfiltered internet in one
step. It **stops the watchdog** (so it can't re-lock) and **unsets the system proxy** on every
network service, so traffic flows directly with no MITM:

- **From the UI** — Settings → **Emergency bypass** → *Restore unfiltered internet* (confirm +
  password). A **Re-enable filtering** button appears while it's active, and the header/dashboard
  show 🟠 *filtering OFF (emergency)*. This works even during an outage, because the installer
  bypasses the proxy for `127.0.0.1`/`localhost`, so the control UI stays reachable.
- **From the terminal** — the ultimate failsafe, works even if the UI daemon is down:
  ```bash
  sudo ./emergency-off.sh        # filtering OFF now, and it stays off
  sudo ./restore-filtering.sh    # re-point the proxy + restart the watchdog
  ```

Both require the admin password (UI) or `sudo` (CLI) — consistent with the tamper model: this
protects against the filtered user, not an administrator. `doctor.sh` reports when emergency
bypass is active.

## Diagnosing problems

When something breaks, you get **plain-English errors with a fix**, not raw tracebacks:

- **`sudo ./doctor.sh`** — one-command health check. Verifies the venv, dependencies, both
  daemons, the proxy/UI ports, the system-proxy setting, the CA trust, Chrome QUIC, fail-open
  state, config permissions, and recent errors. Every failure prints a `->` line with the exact
  command to fix it. Also runnable from the UI: **Diagnostics → Run health check**.
- **`config/filter-errors.log`** — any error caught inside the proxy's request/response hooks is
  logged here (throttled per unique error) with the request URL, the reason, a `FIX:` hint, and
  the traceback — instead of being silently swallowed. A filtering bug still fails open per
  request, but it no longer disappears without a trace.
- **`config/health.log`** — the watchdog runs `doctor.sh` automatically at the start of any
  outage and appends the diagnosis here, so there's always a fresh "what's wrong / how to fix"
  report even for a failure you weren't watching. The UI's Diagnostics panel shows its tail.
- **`config/watchdog.log`** — a timestamped record of every restart, fail-open, and re-lock.

## Known limits (MITM realities)
- **It decrypts all HTTPS.** Guard the CA key in `mitm-ca/`; keep it off shared locations.
- **Certificate pinning** — some sites/native apps pin certs and fail through the proxy. Add
  them to the **Bypass (no-intercept)** list in the UI — those are tunnelled through untouched
  (not decrypted/filtered/logged), which fixes the breakage. Applies to new connections.
- **QUIC/HTTP-3** — Chrome bypasses the proxy via HTTP-3 unless disabled. The installer opens
  the **`chrome-disable-quic.mobileconfig`** profile for this (a pf UDP-443 block does **not**
  work on macOS). Approve it and restart Chrome.
- **Apps that ignore the system proxy** aren't filtered (most browsers honor it).

## Config by hand (optional)
Everything the UI does is just files in `config/` — edit `rules.json` / `keywords.txt`
directly if you prefer; the proxy picks up changes within ~2s.

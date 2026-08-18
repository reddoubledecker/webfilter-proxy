'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(method, path, body) {
  const r = await fetch(path, {
    method, headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  try { return await r.json(); } catch (_) { return { ok: false, error: 'Bad response' }; }
}

// ── Theme (dark mode) ────────────────────────────────────────────────────────────
const THEME_KEY = 'wf-theme';
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem(THEME_KEY, t);
  const b = $('theme-btn'); if (b) b.textContent = t === 'dark' ? '☀️' : '🌙';
}
setTheme(localStorage.getItem(THEME_KEY) ||
  (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
$('theme-btn').onclick = () =>
  setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');

let rulesCache = [];
let kwCache = [];
let rulesSort = 0;        // 0 = stored order, 1 = A→Z, 2 = Z→A
let kwShown = false;      // keywords hidden by default

// ── Boot / gate ──────────────────────────────────────────────────────────────────
async function boot() {
  const s = await api('GET', '/api/state');
  if (!s.hasPassword) return showGate('setup');
  if (!s.authed) return showGate('login');
  showApp();
}
function showGate(which) {
  $('app').classList.add('hidden');
  $('gate').classList.remove('hidden');
  $('setup-view').classList.toggle('hidden', which !== 'setup');
  $('login-view').classList.toggle('hidden', which !== 'login');
}
$('setup-btn').onclick = async () => {
  const pw = $('setup-pw').value, pw2 = $('setup-pw2').value;
  if (pw.length < 4) return $('setup-err').textContent = 'Min 4 characters.';
  if (pw !== pw2) return $('setup-err').textContent = 'Passwords do not match.';
  const r = await api('POST', '/api/password', { next: pw });
  if (r.ok) showApp(); else $('setup-err').textContent = r.error || 'Failed.';
};
$('login-btn').onclick = async () => {
  const r = await api('POST', '/api/login', { password: $('login-pw').value });
  if (r.ok) { $('login-pw').value = ''; showApp(); } else $('login-err').textContent = r.error || 'Failed.';
};
$('login-pw').addEventListener('keydown', e => { if (e.key === 'Enter') $('login-btn').click(); });
// ── Auto-lock: 1 min idle, and on closing the page ────────────────────────────────
const IDLE_MS = 60000;         // lock after 1 minute with no interaction
const HEARTBEAT_MS = 20000;    // while active, keep the server session alive (< idle timeout)
let idleTimer = null, lastBeat = 0, sessionActive = false;

async function lock(reason) {
  if (!sessionActive) return;
  sessionActive = false;
  clearTimeout(idleTimer);
  try { await api('POST', '/api/logout'); } catch (_) {}
  showGate('login');
  $('login-err').textContent = reason || '';
}

function bumpIdle() {
  if (!sessionActive) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => lock('Locked after 1 minute of inactivity.'), IDLE_MS);
  const now = Date.now();
  if (now - lastBeat > HEARTBEAT_MS) {          // let the server know we're still here
    lastBeat = now;
    api('POST', '/api/heartbeat').then(r => { if (r && r.ok === false) lock('Session expired.'); });
  }
}

function startSession() { sessionActive = true; lastBeat = Date.now(); bumpIdle(); }

['mousemove', 'mousedown', 'keydown', 'scroll', 'wheel', 'touchstart'].forEach(
  ev => window.addEventListener(ev, bumpIdle, { passive: true }));
// Lock immediately when the page is closed / navigated away / refreshed.
window.addEventListener('pagehide', () => { if (sessionActive) navigator.sendBeacon('/api/logout'); });

$('lock-btn').onclick = () => lock();

async function showApp() {
  $('gate').classList.add('hidden');
  $('app').classList.remove('hidden');
  startSession();                 // begin the idle-lock timer + heartbeats
  showPane('dashboard');          // land on the dashboard; each pane loads its data on open
}

// ── Sidebar navigation (load each pane's data on demand) ──────────────────────────
const PANE_LOADERS = {
  dashboard: refreshDashboard,
  filtering: () => showSub(currentSub),   // Filtering has its own sub-tabs
  bypass: async () => { await refreshBypass(); await loadBundles(); await refreshSuggestions(); },
  activity: refreshLog,
  diagnostics: refreshHealth,
  settings: () => {},
};
function showPane(name) {
  document.querySelectorAll('.pane').forEach(p => p.classList.add('hidden'));
  const pane = $('pane-' + name); if (pane) pane.classList.remove('hidden');
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.pane === name));
  window.scrollTo(0, 0);
  const load = PANE_LOADERS[name]; if (load) load();
}
$('sidebar').addEventListener('click', e => {
  const b = e.target.closest('.nav-item'); if (b) showPane(b.dataset.pane);
});

// Sub-tabs inside the Filtering pane (Detection · URL rules · Keywords · Detected).
const SUB_LOADERS = { detection: refreshState, rules: refreshRules, keywords: refreshKeywords, detected: refreshLearned };
let currentSub = 'detection';
function showSub(name) {
  currentSub = name;
  document.querySelectorAll('#pane-filtering .subpane').forEach(p => p.classList.add('hidden'));
  const sp = $('sub-' + name); if (sp) sp.classList.remove('hidden');
  document.querySelectorAll('#filtering-subtabs .subtab').forEach(b => b.classList.toggle('active', b.dataset.sub === name));
  const load = SUB_LOADERS[name]; if (load) load();
}
$('filtering-subtabs').addEventListener('click', e => {
  const b = e.target.closest('.subtab'); if (b) showSub(b.dataset.sub);
});

// ── Dashboard ─────────────────────────────────────────────────────────────────────
async function refreshDashboard() {
  await refreshState();                          // header status + stat numbers
  const r = await api('GET', '/api/log?per_page=10&page=0&kind=activity');
  const body = $('dash-log-body'); if (!body) return;
  const rows = (r && r.log) || [];
  body.innerHTML = '';
  $('dash-log-empty').classList.toggle('hidden', rows.length > 0);
  for (const e of rows) {
    const tr = document.createElement('tr');
    const act = e.action === 'blocked'
      ? '<span class="tag block">blocked</span>' : '<span class="tag allow">allowed</span>';
    tr.innerHTML = `<td>${esc((e.t || '').replace('T', ' '))}</td><td>${act}</td>` +
      `<td class="url">${esc(e.url || e.host || '')}</td>`;
    body.appendChild(tr);
  }
}
$('dash-refresh').onclick = refreshDashboard;

// ── Diagnostics ──────────────────────────────────────────────────────────────────
async function refreshHealth() {
  const r = await api('GET', '/api/health');
  if (r && r.log) $('health-out').textContent = r.log.trim();
}
$('run-health').onclick = async () => {
  $('health-msg').textContent = 'Running…';
  $('run-health').disabled = true;
  const r = await api('POST', '/api/health/run');
  $('health-out').textContent = (r && r.output ? r.output.trim() : '') || 'No output.';
  $('health-msg').textContent = '';
  $('run-health').disabled = false;
};

// ── Detection: safesearch, threshold, categories ─────────────────────────────────
async function refreshState() {
  const s = await api('GET', '/api/state');
  $('safesearch').checked = s.safeSearch;
  $('banner').checked = s.banner;
  $('bypass-all').checked = s.bypassAll;
  $('bypass-warning').classList.toggle('hidden', !s.bypassAll);
  $('threshold').value = String(s.threshold);
  $('proxy-status').textContent = s.emergency ? '🟠 filtering OFF (emergency)'
    : (s.proxyUp ? '🟢 filter active' : '🔴 filter down');
  $('filter-down-warning').classList.toggle('hidden', !s.failOpen);
  if ($('emg-idle')) {                            // emergency-bypass buttons
    $('emg-idle').classList.toggle('hidden', s.emergency);
    $('emg-active').classList.toggle('hidden', !s.emergency);
  }
  if ($('dash-proxy')) {                          // dashboard stat cards
    $('dash-proxy').textContent = s.emergency ? '🟠 OFF' : (s.proxyUp ? '🟢 Active' : '🔴 Down');
    $('dash-rules').textContent = s.ruleCount;
    $('dash-keywords').textContent = s.keywordCount;
    $('dash-learned').textContent = s.learnedCount;
  }
  const box = $('categories'); box.innerHTML = '';
  for (const c of s.categories || []) {
    const l = document.createElement('label');
    l.innerHTML = `<input type="checkbox" data-cat="${esc(c.id)}" ${c.enabled ? 'checked' : ''}> ${esc(c.label)}`;
    box.appendChild(l);
  }
}
$('safesearch').onchange = e => api('PATCH', '/api/config', { safeSearch: e.target.checked });
$('banner').onchange = e => api('PATCH', '/api/config', { banner: e.target.checked });
$('bypass-all').onchange = async e => {
  if (e.target.checked) {
    const pw = await askPassword('Enter your password to bypass ALL filtering');
    if (pw == null) { e.target.checked = false; return; }
    const r = await api('POST', '/api/bypassall', { enabled: true, password: pw });
    if (!r.ok) { e.target.checked = false; alert(r.error || 'Incorrect password.'); }
  } else {
    await api('POST', '/api/bypassall', { enabled: false });
  }
  refreshState();
};

// ── Emergency bypass (kill switch) ────────────────────────────────────────────────
$('emergency-off-btn').onclick = async () => {
  if (!confirm('Turn OFF all filtering now?\n\nThis stops the watchdog and unsets the system proxy so browsing works unfiltered until you re-enable it.')) return;
  const pw = await askPassword('Enter your password to turn filtering OFF (emergency)');
  if (pw == null) return;
  $('emergency-msg').textContent = 'Working…';
  const r = await api('POST', '/api/bypass/emergency', { password: pw });
  $('emergency-msg').textContent = '';
  if (!r.ok) return alert(r.error || 'Failed.');
  refreshState();
};
$('emergency-restore-btn').onclick = async () => {
  const pw = await askPassword('Enter your password to re-enable filtering');
  if (pw == null) return;
  $('emergency-msg').textContent = 'Working…';
  const r = await api('POST', '/api/bypass/restore', { password: pw });
  $('emergency-msg').textContent = '';
  if (!r.ok) return alert(r.error || 'Failed.');
  refreshState();
};
$('bypass-off').onclick = async () => { await api('POST', '/api/bypassall', { enabled: false }); refreshState(); };
$('threshold').onchange = e => api('PATCH', '/api/config', { threshold: Number(e.target.value) });
$('categories').addEventListener('change', e => {
  if (e.target.dataset.cat) api('PATCH', '/api/config', { categories: { [e.target.dataset.cat]: e.target.checked } });
});

// ── Rules ────────────────────────────────────────────────────────────────────────
async function refreshRules() {
  const r = await api('GET', '/api/rules');
  rulesCache = r.rules || [];
  const body = $('rules-body'); body.innerHTML = '';
  $('rules-empty').classList.toggle('hidden', rulesCache.length > 0);
  $('rules-sort').textContent = 'Pattern ' + (rulesSort === 1 ? '↑' : rulesSort === 2 ? '↓' : '⇅');
  let view = rulesCache.map((rule, i) => ({ ...rule, _i: i }));   // keep original index for delete
  if (rulesSort === 1) view.sort((a, b) => a.pattern.localeCompare(b.pattern));
  else if (rulesSort === 2) view.sort((a, b) => b.pattern.localeCompare(a.pattern));
  for (const rule of view) {
    const tr = document.createElement('tr');
    const t = rule.type === 'allow' ? 'allow' : 'block';
    tr.innerHTML = `<td><span class="tag ${t}">${t}</span></td><td class="pattern">${esc(rule.pattern)}</td>
      <td><span class="link" data-del="${rule._i}">Delete</span></td>`;
    body.appendChild(tr);
  }
}
$('rules-sort').onclick = () => { rulesSort = (rulesSort + 1) % 3; refreshRules(); };
async function saveRules() { const r = await api('PUT', '/api/rules', { rules: rulesCache }); rulesCache = r.rules || []; refreshRules(); refreshState(); }
$('add-rule').onclick = async () => {
  const pattern = $('rule-pattern').value.trim();
  if (!pattern) return $('rule-err').textContent = 'Enter a pattern.';
  rulesCache.push({ type: $('rule-type').value, pattern });
  $('rule-pattern').value = ''; $('rule-err').textContent = '';
  await saveRules();
};
$('rule-pattern').addEventListener('keydown', e => { if (e.key === 'Enter') $('add-rule').click(); });
$('rules-body').addEventListener('click', async e => {
  if (e.target.dataset.del != null) { rulesCache.splice(Number(e.target.dataset.del), 1); await saveRules(); }
});

// ── Keywords ─────────────────────────────────────────────────────────────────────
async function refreshKeywords() {
  const r = await api('GET', '/api/keywords');
  kwCache = r.keywords || [];
  $('kw-count').textContent = `${kwCache.length} total`;
  const box = $('kw-list'); box.innerHTML = '';
  for (const k of kwCache) {
    const chip = document.createElement('span');
    chip.className = 'kw-chip';
    chip.innerHTML = `${esc(k)}<span class="kw-x" data-kw="${esc(k)}" title="Remove">×</span>`;
    box.appendChild(chip);
  }
  box.classList.toggle('blurred', !kwShown);
}
$('kw-toggle').onclick = () => {
  kwShown = !kwShown;
  $('kw-list').classList.toggle('blurred', !kwShown);
  $('kw-toggle').textContent = kwShown ? 'Hide' : 'Show';
};
$('add-kw').onclick = async () => {
  const text = $('kw-input').value.trim();
  if (!text) return;
  const added = text.split(/[\n,;]+/).map(k => k.trim().toLowerCase()).filter(k => k.length >= 2);
  const merged = [...new Set([...kwCache, ...added])];
  const r = await api('PUT', '/api/keywords', { keywords: merged });
  kwCache = r.keywords || []; $('kw-input').value = '';
  $('kw-msg').textContent = `${kwCache.length} total`; refreshKeywords(); refreshState();
};
$('kw-list').addEventListener('click', async e => {
  if (e.target.dataset.kw != null) {
    const r = await api('PUT', '/api/keywords', { keywords: kwCache.filter(k => k !== e.target.dataset.kw) });
    kwCache = r.keywords || []; refreshKeywords(); refreshState();
  }
});

// ── Bypass (no-intercept) ────────────────────────────────────────────────────────
let bypassCache = [];    // [{pattern, group}]
async function refreshBypass() {
  const r = await api('GET', '/api/bypass');
  bypassCache = r.bypass || [];
  $('bypass-count').textContent = `${bypassCache.length} total`;
  const groups = {};
  for (const e of bypassCache) (groups[e.group || ''] ||= []).push(e.pattern);
  const names = Object.keys(groups).sort((a, b) => (a === '' ? 1 : 0) - (b === '' ? 1 : 0) || a.localeCompare(b));
  const box = $('bypass-list'); box.innerHTML = '';
  for (const g of names) {
    const wrap = document.createElement('div');
    wrap.style.marginTop = '12px';
    wrap.innerHTML = `<div class="muted" style="font-weight:700">${esc(g || 'Ungrouped')}</div>`;
    const list = document.createElement('div'); list.className = 'kw-list'; list.style.marginTop = '6px';
    for (const p of groups[g]) {
      const chip = document.createElement('span'); chip.className = 'kw-chip';
      chip.innerHTML = `${esc(p)}<span class="kw-x" data-bp="${esc(p)}" title="Remove">×</span>`;
      list.appendChild(chip);
    }
    wrap.appendChild(list); box.appendChild(wrap);
  }
}
$('add-bypass').onclick = async () => {
  const text = $('bypass-input').value.trim();
  if (!text) return;
  const group = $('bypass-group').value.trim();
  const existing = new Set(bypassCache.map(e => e.pattern));
  const added = text.split(/[\n,;]+/).map(p => p.trim().toLowerCase()).filter(p => p && !existing.has(p))
    .map(p => ({ pattern: p, group }));
  const r = await api('PUT', '/api/bypass', { bypass: [...bypassCache, ...added] });
  bypassCache = r.bypass || []; $('bypass-input').value = ''; $('bypass-group').value = '';
  $('bypass-msg').textContent = 'Applies to new connections.'; refreshBypass();
};
$('bypass-list').addEventListener('click', async e => {
  if (e.target.dataset.bp != null) {
    const r = await api('PUT', '/api/bypass', { bypass: bypassCache.filter(x => x.pattern !== e.target.dataset.bp) });
    bypassCache = r.bypass || []; refreshBypass();
  }
});

// bundles
async function loadBundles() {
  const r = await api('GET', '/api/bundles');
  const sel = $('bundle-select'); sel.innerHTML = '';
  for (const b of (r.bundles || [])) {
    const o = document.createElement('option');
    o.value = b.name; o.textContent = b.name; sel.appendChild(o);
  }
}
$('add-bundle').onclick = async () => {
  const name = $('bundle-select').value;
  if (!name) return;
  const r = await api('POST', `/api/bundles/${encodeURIComponent(name)}/add`);
  bypassCache = r.bypass || []; refreshBypass();
  $('bypass-msg').textContent = `Added ${name} bundle.`;
};

// suggested related domains
async function refreshSuggestions() {
  const r = await api('GET', '/api/suggestions');
  const list = r.suggestions || [];
  const body = $('suggestions-body'); body.innerHTML = '';
  $('suggestions-empty').classList.toggle('hidden', list.length > 0);
  for (const s of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="pattern">${esc(s.domain)}</td>
      <td class="muted">${esc((s.parents || []).join(', '))}</td>
      <td>${esc(String(s.count ?? ''))}</td>
      <td><span class="link keep" data-add="${esc(s.domain)}">Add to bypass</span><span class="link" data-dis="${esc(s.domain)}">Dismiss</span></td>`;
    body.appendChild(tr);
  }
}
$('refresh-suggestions').onclick = refreshSuggestions;
$('suggestions-body').addEventListener('click', async e => {
  const el = e.target;
  if (el.dataset.add != null) {
    const r = await api('POST', `/api/suggestions/${encodeURIComponent(el.dataset.add)}/add`);
    bypassCache = r.bypass || []; refreshBypass(); refreshSuggestions();
  } else if (el.dataset.dis != null) {
    await api('DELETE', `/api/suggestions/${encodeURIComponent(el.dataset.dis)}`);
    refreshSuggestions();
  }
});

// ── Learned ──────────────────────────────────────────────────────────────────────
async function refreshLearned() {
  const r = await api('GET', '/api/learned');
  const list = r.learned || [];
  const body = $('learned-body'); body.innerHTML = '';
  $('learned-empty').classList.toggle('hidden', list.length > 0);
  for (const rec of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="pattern">${esc(rec.host)}</td><td><span class="tag cat">${esc(rec.label || rec.category || '')}</span></td>
      <td>${esc(String(rec.score ?? ''))}</td>
      <td><span class="link keep" data-promote="${esc(rec.host)}">Promote</span><span class="link" data-dell="${esc(rec.host)}">Delete</span></td>`;
    body.appendChild(tr);
  }
}
$('learned-body').addEventListener('click', async e => {
  const el = e.target;
  if (el.dataset.promote != null) { await api('POST', `/api/learned/${encodeURIComponent(el.dataset.promote)}/promote`); refreshLearned(); refreshRules(); refreshState(); }
  else if (el.dataset.dell != null) { await api('DELETE', `/api/learned/${encodeURIComponent(el.dataset.dell)}`); refreshLearned(); refreshState(); }
});
$('refresh-learned').onclick = () => { refreshLearned(); refreshState(); };
$('clear-learned').onclick = async () => {
  const pw = await askPassword('Enter your password to clear all auto-detected domains');
  if (pw == null) return;
  const r = await api('POST', '/api/learned/clear', { password: pw });
  if (r.ok) { refreshLearned(); refreshState(); } else alert(r.error || 'Failed to clear.');
};

// ── Activity log (paginated, 50/page) ────────────────────────────────────────────
let logPage = 0;
async function refreshLog() {
  const kind = $('log-kind').value;
  const q = encodeURIComponent($('log-q').value.trim());
  const r = await api('GET', `/api/log?kind=${kind}&q=${q}&page=${logPage}&per_page=50&days=30`);
  const list = r.log || [];
  const body = $('log-body'); body.innerHTML = '';
  $('log-empty').classList.toggle('hidden', list.length > 0);
  for (const e of list) {
    const tr = document.createElement('tr');
    const time = (e.t || '').replace('T', ' ');
    const action = e.action === 'blocked'
      ? '<span class="tag block">Blocked</span>' : '<span class="tag allow">Allowed</span>';
    const mid = e.query ? `<span class="tag cat">🔍 ${esc(e.query)}</span>` : esc(e.reason || '');
    tr.innerHTML = `<td>${esc(time)}</td><td>${action}</td><td>${mid}</td><td class="url">${esc(e.url || '')}</td>`;
    body.appendChild(tr);
  }
  $('log-page').textContent = `Page ${logPage + 1}`;
  $('log-prev').disabled = logPage <= 0;
  $('log-next').disabled = !r.hasMore;
}
function reloadLog() { logPage = 0; refreshLog(); }   // filter/search change → back to page 1
$('refresh-log').onclick = reloadLog;
$('log-kind').onchange = reloadLog;
$('log-q').addEventListener('keydown', e => { if (e.key === 'Enter') reloadLog(); });
$('log-prev').onclick = () => { if (logPage > 0) { logPage--; refreshLog(); } };
$('log-next').onclick = () => { logPage++; refreshLog(); };
function askPassword(title) {
  return new Promise(resolve => {
    $('pw-modal-title').textContent = title;
    $('pw-modal-err').textContent = '';
    $('pw-modal-input').value = '';
    $('pw-modal').classList.remove('hidden');
    $('pw-modal-input').focus();
    const done = v => { $('pw-modal').classList.add('hidden'); cleanup(); resolve(v); };
    const onOk = () => done($('pw-modal-input').value);
    const onCancel = () => done(null);
    const onKey = e => { if (e.key === 'Enter') onOk(); else if (e.key === 'Escape') onCancel(); };
    function cleanup() {
      $('pw-modal-ok').removeEventListener('click', onOk);
      $('pw-modal-cancel').removeEventListener('click', onCancel);
      $('pw-modal-input').removeEventListener('keydown', onKey);
    }
    $('pw-modal-ok').addEventListener('click', onOk);
    $('pw-modal-cancel').addEventListener('click', onCancel);
    $('pw-modal-input').addEventListener('keydown', onKey);
  });
}
$('clear-log').onclick = async () => {
  const pw = await askPassword('Enter your password to clear the activity log');
  if (pw == null) return;
  const r = await api('POST', '/api/log/clear', { password: pw });
  if (r.ok) { logPage = 0; refreshLog(); } else alert(r.error || 'Failed to clear.');
};
$('export-csv').onclick = () => {
  const kind = $('log-kind').value;
  const q = encodeURIComponent($('log-q').value.trim());
  window.location = `/api/log.csv?kind=${kind}&q=${q}&days=30`;   // same-origin cookie → downloads
};

// ── Change password ──────────────────────────────────────────────────────────────
$('change-pw').onclick = async () => {
  $('pw-err').textContent = ''; $('pw-ok').textContent = '';
  const r = await api('POST', '/api/password', { current: $('cur-pw').value, next: $('new-pw').value });
  if (r.ok) { $('cur-pw').value = $('new-pw').value = ''; $('pw-ok').textContent = 'Password updated.'; }
  else $('pw-err').textContent = r.error || 'Failed.';
};

// ── Backup / transfer ────────────────────────────────────────────────────────────
$('export-btn').onclick = () => { window.location = '/api/export'; };
$('import-file').addEventListener('change', async e => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    const data = JSON.parse(await f.text());
    const pw = await askPassword('Enter your password to import (this replaces settings)');
    if (pw == null) { e.target.value = ''; return; }
    const r = await api('POST', '/api/import', { password: pw, config: data });
    if (r.ok) { $('backup-msg').textContent = 'Imported — reloading…'; await showApp(); }
    else $('backup-msg').textContent = r.error || 'Import failed.';
  } catch (_) {
    $('backup-msg').textContent = 'Invalid config file.';
  }
  e.target.value = '';
});

boot();

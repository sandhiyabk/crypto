/*
 * app.js — browser-side prover + UI for the ZK anonymous-auth demo.
 * Uses the shared window.ZK crypto module loaded from /lib/zk.js.
 */
'use strict';

/* ------------------------------------------------------------------ *
 *  Small helpers
 * ------------------------------------------------------------------ */
const $ = (id) => document.getElementById(id);
const hex = (x) => x.toString(16);
const unhex = (h) => BigInt('0x' + h);
const short = (s) => (s.length <= 42 ? s : s.slice(0, 26) + '…' + s.slice(-14));

async function api(pathname, opts) {
  const res = await fetch(pathname, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  return res.json();
}

function line(cls, text) {
  const span = document.createElement('span');
  span.className = 't-line ' + (cls || '');
  span.textContent = text;
  return span;
}
function append(el, cls, text) { el.appendChild(line(cls, text)); el.scrollTop = el.scrollHeight; }
function clear(el) { el.innerHTML = ''; }

/* ------------------------------------------------------------------ *
 *  State
 * ------------------------------------------------------------------ */
const state = {
  identity: null,        // { name, x, y }
  knownSecrets: [],      // [{ name, x, y }]  (identity + seeded demo members)
  registry: [],          // [{ id, name, y(hex) }] as known by the server
  interactive: null
};

/* ------------------------------------------------------------------ *
 *  Server status
 * ------------------------------------------------------------------ */
async function ping() {
  try {
    const p = await api('/api/params');
    $('server-dot').className = 'dot on';
    $('server-status').textContent = 'verifier online';
    clear($('params-out'));
    const out = $('params-out');
    append(out, 't-label', 'algorithm : ');
    out.lastChild.className = 't-line';
    append(out, 't-val', p.algorithm);
    append(out, 't-label', 'p (bits)  : ');
    append(out, 't-val', String(p.pBits));
    append(out, 't-label', 'p         : ');
    append(out, 't-val', short('0x' + p.p));
    append(out, 't-label', 'q         : ');
    append(out, 't-val', short('0x' + p.q));
    append(out, 't-label', 'g         : ');
    append(out, 't-val', short('0x' + p.g));
  } catch {
    $('server-dot').className = 'dot off';
    $('server-status').textContent = 'offline';
  }
}

/* ------------------------------------------------------------------ *
 *  Tabs
 * ------------------------------------------------------------------ */
document.querySelectorAll('.nav-item').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    $('tab-' + tab).classList.add('active');
    $('page-title').textContent = btn.textContent.replace(/^[^A-Za-z]+/, '').trim();
  });
});

/* ------------------------------------------------------------------ *
 *  Identity
 * ------------------------------------------------------------------ */
function renderIdentity() {
  const out = $('identity-out');
  clear(out);
  const id = state.identity;
  if (!id) {
    out.innerHTML = '<div class="kv-empty">No keypair yet — generate one to begin.</div>';
    $('id-chip').textContent = 'no identity';
    return;
  }
  const row = (k, v, cls) => {
    const r = document.createElement('div');
    r.className = 'kv-row';
    r.innerHTML = `<div class="kv-key">${k}</div><div class="kv-val ${cls || ''}">${v}</div>`;
    out.appendChild(r);
  };
  row('name', id.name);
  row('secret x (never sent)', short(hex(id.x)), 'secret');
  row('public y = g^x mod p', short(hex(id.y)), 'pub');
  row('registered as', id.serverId ? `#${id.serverId}` : 'not registered', id.serverId ? '' : 'secret');
  $('id-chip').textContent = id.name + (id.serverId ? ' · registered' : ' · local');
}

$('btn-gen').addEventListener('click', () => {
  const name = ($('in-name').value || 'alice').trim();
  const { x, y } = ZK.keygen();
  state.identity = { name, x, y, serverId: null };
  addKnownSecret(name, x, y);
  $('btn-register').disabled = false;
  renderIdentity();
});

$('btn-register').addEventListener('click', async () => {
  const id = state.identity;
  if (!id) return;
  const r = await api('/api/register', {
    method: 'POST',
    body: JSON.stringify({ name: id.name, y: hex(id.y) })
  });
  if (r.ok) {
    id.serverId = r.member.id;
    renderIdentity();
    await loadRegistry();
    refreshLog();
  }
});

$('btn-seed').addEventListener('click', async () => {
  const names = ['bob', 'carol', 'dave', 'erin'];
  for (const name of names) {
    if (state.knownSecrets.some((k) => k.name === name)) continue;
    const { x, y } = ZK.keygen();
    addKnownSecret(name, x, y);
    await api('/api/register', { method: 'POST', body: JSON.stringify({ name, y: hex(y) }) });
  }
  await loadRegistry();
  refreshLog();
});

function addKnownSecret(name, x, y) {
  const existing = state.knownSecrets.find((k) => k.name === name);
  if (existing) { existing.x = x; existing.y = y; return; }
  state.knownSecrets.push({ name, x, y });
}

async function loadRegistry() {
  const r = await api('/api/registry');
  state.registry = r.members || [];
  const out = $('registry-out');
  clear(out);
  if (!state.registry.length) {
    out.innerHTML = '<span class="muted">empty</span>';
  } else {
    for (const m of state.registry) {
      const div = document.createElement('div');
      div.className = 'reg-item';
      div.innerHTML = `<span class="reg-name">${m.name}</span><span class="reg-key">y = 0x${short(m.y)}</span>`;
      out.appendChild(div);
    }
  }
  renderSignerSelect();
}

/* ------------------------------------------------------------------ *
 *  Interactive Schnorr handshake
 * ------------------------------------------------------------------ */
$('btn-gen').addEventListener('click', resetInteractive);

function resetInteractive() {
  state.interactive = null;
  $('int-step2').disabled = true;
  $('int-step3').disabled = true;
  const eq = $('int-eq');
  eq.className = 'eq';
  eq.textContent = 'equation check appears after step 3';
  clear($('int-transcript'));
}

$('int-reset').addEventListener('click', resetInteractive);

$('int-step1').addEventListener('click', () => {
  const id = state.identity;
  const out = $('int-transcript');
  if (!id) { append(out, 't-bad', '[!] generate an identity first (Identity & Keys tab)'); return; }
  const { r, t } = ZK.schnorrCommit();
  state.interactive = { r, t, y: id.y, x: id.x, c: null, sessionId: null };
  append(out, 't-step', '── Step 1 · prover commits ──');
  append(out, 't-label', 'pick r  (secret random)   : ');
  append(out, 't-val', short(hex(r)));
  append(out, 't-in', 't = g^r mod p              : ');
  append(out, 't-val', short(hex(t)));
  $('int-step2').disabled = false;
});

$('int-step2').addEventListener('click', async () => {
  const st = state.interactive;
  if (!st) return;
  const out = $('int-transcript');
  const r = await api('/api/auth/interactive/commit', {
    method: 'POST',
    body: JSON.stringify({ y: hex(st.y), t: hex(st.t) })
  });
  if (!r.ok) { append(out, 't-bad', '[!] server rejected commitment: ' + r.error); return; }
  st.c = unhex(r.challenge);
  st.sessionId = r.sessionId;
  append(out, 't-step', '\n── Step 2 · verifier challenges ──');
  append(out, 't-label', 'send t to server           : ✓');
  append(out, 't-out', 'challenge c (random)       : ');
  append(out, 't-val', short(r.challenge));
  $('int-step3').disabled = false;
});

$('int-step3').addEventListener('click', async () => {
  const st = state.interactive;
  if (!st || st.c === null) return;
  const out = $('int-transcript');
  const s = ZK.schnorrRespond(st.r, st.c, st.x);
  append(out, 't-step', '\n── Step 3 · prover responds ──');
  append(out, 't-out', 's = r + c·x mod q          : ');
  append(out, 't-val', short(hex(s)));

  const r = await api('/api/auth/interactive/respond', {
    method: 'POST',
    body: JSON.stringify({ sessionId: st.sessionId, s: hex(s) })
  });

  const lhs = ZK.modPow(ZK.G, ZK.mod(s, ZK.Q), ZK.P);
  const rhs = ZK.mod(st.t * ZK.modPow(st.y, ZK.mod(st.c, ZK.Q), ZK.P), ZK.P);
  const eq = $('int-eq');
  append(out, 't-label', 'server checks g^s == t·y^c : ');
  append(out, r.ok ? 't-ok' : 't-bad', r.ok ? 'ACCEPTED' : 'REJECTED (' + r.error + ')');
  eq.className = 'eq ' + (lhs === rhs ? 'pass' : 'fail');
  eq.textContent = 'g^s mod p  =  0x' + short(hex(lhs)) + '\n' +
                   't·y^c mod p = 0x' + short(hex(rhs)) + '\n' +
                   (lhs === rhs ? '✓ equality holds — the server is convinced, x was never revealed'
                                : '✗ mismatch');
  if (r.identity) append(out, 't-ok', 'authenticated as: ' + r.identity.name);
  refreshLog();
});

/* ------------------------------------------------------------------ *
 *  Non-interactive ZK login
 * ------------------------------------------------------------------ */
$('nizk-run').addEventListener('click', async () => {
  const id = state.identity;
  const out = $('nizk-transcript');
  const vd = $('nizk-verdict');
  clear(out);
  if (!id) { vd.className = 'verdict fail'; vd.textContent = 'Generate an identity first.'; return; }

  vd.className = 'verdict pending';
  vd.textContent = 'requesting nonce…';
  const { nonce } = await api('/api/nonce?prefix=auth');

  append(out, 't-step', '── Fiat–Shamir proof of knowledge ──');
  append(out, 't-label', 'server nonce (single use)  : ');
  append(out, 't-val', nonce);

  const proof = ZK.nizkProve(id.x, id.y, nonce);
  append(out, 't-in', 't = g^r mod p              : ');
  append(out, 't-val', short(hex(proof.t)));
  append(out, 't-out', 'c = H(g,y,t,nonce) mod q   : ');
  append(out, 't-val', short(hex(proof.c)));
  append(out, 't-in', 's = r + c·x mod q          : ');
  append(out, 't-val', short(hex(proof.s)));
  append(out, 't-label', 'x (secret) transmitted?    : ');
  append(out, 't-ok', 'NO — stays in this browser');

  const r = await api('/api/auth/nizk', {
    method: 'POST',
    body: JSON.stringify({ y: hex(id.y), proof: { t: hex(proof.t), s: hex(proof.s) }, message: nonce })
  });

  append(out, 't-label', 'server verdict             : ');
  append(out, r.ok ? 't-ok' : 't-bad', r.ok ? 'ACCEPTED' : 'REJECTED (' + r.error + ')');
  if (r.identity) append(out, 't-ok', 'authenticated as           : ' + r.identity.name);

  vd.className = 'verdict ' + (r.ok ? 'pass' : 'fail');
  vd.textContent = r.ok
    ? '✓ Login accepted. Server is convinced the prover knows x — without learning x.'
    : '✗ Login rejected: ' + r.error;

  // Demonstrate replay protection.
  const replay = await api('/api/auth/nizk', {
    method: 'POST',
    body: JSON.stringify({ y: hex(id.y), proof: { t: hex(proof.t), s: hex(proof.s) }, message: nonce })
  });
  append(out, 't-label', 'replay same proof again     : ');
  append(out, 't-bad', replay.ok ? 'accepted (unexpected!)' : 'REJECTED — nonce already used');
  refreshLog();
});

/* ------------------------------------------------------------------ *
 *  Anonymous group authentication (ring signature)
 * ------------------------------------------------------------------ */
function renderSignerSelect() {
  const sel = $('ring-signer');
  const regSet = new Set(state.registry.map((m) => m.y));
  const available = state.knownSecrets.filter((k) => regSet.has(hex(k.y)));
  const current = sel.value;
  sel.innerHTML = '';
  if (!available.length) {
    const o = document.createElement('option');
    o.textContent = 'no registered keys you own';
    o.disabled = true;
    sel.appendChild(o);
    return;
  }
  for (const k of available) {
    const o = document.createElement('option');
    o.value = k.name;
    o.textContent = k.name;
    sel.appendChild(o);
  }
  if (available.some((k) => k.name === current)) sel.value = current;
}

$('ring-run').addEventListener('click', async () => {
  const out = $('ring-transcript');
  const vd = $('ring-verdict');
  clear(out);

  const ring = state.registry.map((m) => unhex(m.y));
  if (ring.length < 2) {
    vd.className = 'verdict fail';
    vd.textContent = 'Register at least two members (use "Seed 4 demo members").';
    return;
  }
  const signerName = $('ring-signer').value;
  const signer = state.knownSecrets.find((k) => k.name === signerName);
  if (!signer) { vd.className = 'verdict fail'; vd.textContent = 'Pick a signer identity.'; return; }
  const idx = ring.findIndex((y) => y === signer.y);

  vd.className = 'verdict pending';
  vd.textContent = 'requesting nonce…';
  const { nonce } = await api('/api/nonce?prefix=ring');

  const sig = ZK.ringSign(nonce, ring, idx, signer.x);

  append(out, 't-step', '── Anonymous ring signature ──');
  append(out, 't-label', 'server nonce (single use)  : ');
  append(out, 't-val', nonce);
  append(out, 't-label', 'anonymity set size (n)     : ');
  append(out, 't-val', String(ring.length) + '  [' + state.registry.map((m) => m.name).join(', ') + ']');
  append(out, 't-label', 'c = (c_0 … c_n-1)          : ');
  append(out, 't-val', sig.c.map((x) => short(hex(x))).join(', '));
  append(out, 't-label', 'z = (z_0 … z_n-1)          : ');
  append(out, 't-val', sig.z.map((x) => short(hex(x))).join(', '));
  append(out, 't-label', 'signer index in signature? : ');
  append(out, 't-ok', 'NOT INCLUDED — all n pairs are uniform');

  const r = await api('/api/ring/verify', {
    method: 'POST',
    body: JSON.stringify({
      message: nonce,
      ring: state.registry.map((m) => m.y),
      signature: { c: sig.c.map(hex), z: sig.z.map(hex) }
    })
  });

  append(out, 't-label', 'server verdict             : ');
  append(out, r.ok ? 't-ok' : 't-bad', r.ok ? 'VALID RING SIGNATURE' : 'REJECTED (' + r.error + ')');
  if (r.anonymitySet) {
    append(out, 't-label', 'server learns signer ∈     : ');
    append(out, 't-out', '{ ' + r.anonymitySet.join(', ') + ' }');
  }
  if ($('ring-reveal').checked) {
    append(out, 't-label', 'true signer (local only)   : ');
    append(out, 't-warn t-val', signerName);
  }

  vd.className = 'verdict ' + (r.ok ? 'pass' : 'fail');
  vd.textContent = r.ok
    ? '✓ Accepted. The server verified a group member signed but cannot determine which.'
    : '✗ Rejected: ' + r.error;

  refreshLog();
});

/* ------------------------------------------------------------------ *
 *  Audit log
 * ------------------------------------------------------------------ */
$('log-refresh').addEventListener('click', refreshLog);

async function refreshLog() {
  try {
    const r = await api('/api/log');
    const out = $('log-out');
    clear(out);
    for (const e of (r.entries || [])) {
      const div = document.createElement('div');
      div.className = 'log-entry';
      const t = new Date(e.time).toLocaleTimeString();
      div.innerHTML = `<span class="log-time">${t}</span>` +
                      `<span class="log-type">${e.type}</span>` +
                      `<span class="log-msg">${e.message}</span>`;
      out.appendChild(div);
    }
  } catch { /* ignore */ }
}

/* ------------------------------------------------------------------ *
 *  Boot
 * ------------------------------------------------------------------ */
(async function boot() {
  await ping();
  await loadRegistry();
  refreshLog();
  setInterval(refreshLog, 4000);
})();

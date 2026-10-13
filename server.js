/*
 * server.js — Verifier / authenticator for the ZK anonymous-auth demo.
 *
 * Acts as the relying party ("network service") that:
 *   - keeps a public-key directory of registered identities
 *   - verifies Schnorr NIZK proofs of knowledge
 *   - runs the interactive Schnorr challenge/response handshake
 *   - verifies AOS ring signatures for anonymous group authentication
 *
 * No third-party dependencies: built on Node's `http` module only.
 * Run with: `npm start`
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const ZK = require('./lib/zk');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const LIB_DIR = path.join(__dirname, 'lib');

/* ------------------------------------------------------------------ *
 *  In-memory state
 * ------------------------------------------------------------------ */
const registry = new Map();           // id -> { id, name, y: bigint }
const sessions = new Map();           // sessionId -> { y, t, challenge, expires }
const unclaimed = new Map();          // nonce -> { expires }
const auditLog = [];                  // recent verification events

const SESSION_TTL = 2 * 60 * 1000;
const NONCE_TTL = 2 * 60 * 1000;

function logEvent(type, message, meta) {
  const entry = { time: new Date().toISOString(), type, message, meta: meta || null };
  auditLog.unshift(entry);
  if (auditLog.length > 100) auditLog.pop();
  return entry;
}

function sweep() {
  const now = Date.now();
  for (const [k, v] of sessions) if (v.expires < now) sessions.delete(k);
  for (const [k, v] of unclaimed) if (v.expires < now) unclaimed.delete(k);
}
setInterval(sweep, 30 * 1000).unref();

/* ------------------------------------------------------------------ *
 *  Serialization helpers (BigInt <-> hex)
 * ------------------------------------------------------------------ */
const hex = (x) => x.toString(16);
const unhex = (h) => BigInt('0x' + h);
const randId = () => ZK.bytesToBigInt(ZK.randomBytes(8)).toString(16);

function memberView(m) { return { id: m.id, name: m.name, y: hex(m.y) }; }

function nonceString(prefix) {
  const n = ZK.bytesToBigInt(ZK.randomBytes(16)).toString(16).padStart(32, '0');
  return (prefix || 'auth') + ':' + n;
}

/* ------------------------------------------------------------------ *
 *  HTTP plumbing
 * ------------------------------------------------------------------ */
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 1e6) { reject(new Error('payload too large')); req.destroy(); }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveFile(res, baseDir, relPath) {
  const safe = path.normalize(relPath).replace(/^(\.\.[/\\])+/, '');
  const full = path.join(baseDir, safe);
  if (!full.startsWith(baseDir)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
    res.end(data);
  });
}

/* ------------------------------------------------------------------ *
 *  API routes
 * ------------------------------------------------------------------ */
async function handleApi(req, res, url) {
  const route = req.method + ' ' + url.pathname;

  switch (route) {
    /* Group parameters (public). */
    case 'GET /api/params':
      return sendJson(res, 200, {
        p: hex(ZK.P), q: hex(ZK.Q), g: hex(ZK.G),
        pBits: ZK.P.toString(2).length,
        algorithm: 'RFC 3526 MODP Group 14 (2048-bit safe prime)'
      });

    /* Directory of registered public keys. */
    case 'GET /api/registry':
      return sendJson(res, 200, {
        members: [...registry.values()].map(memberView)
      });

    /* Register a public key y = g^x. The secret x never leaves the browser. */
    case 'POST /api/register': {
      const body = await readBody(req);
      if (!body.y) return sendJson(res, 400, { ok: false, error: 'missing public key y' });
      let y;
      try { y = unhex(body.y); } catch { return sendJson(res, 400, { ok: false, error: 'bad public key' }); }
      if (y <= 1n || y >= ZK.P) return sendJson(res, 400, { ok: false, error: 'public key out of range' });

      const id = randId();
      const name = (body.name || 'anon-' + id).toString().slice(0, 40);
      registry.set(id, { id, name, y });
      logEvent('register', `Identity "${name}" registered with public key g^x`, { id });
      return sendJson(res, 200, { ok: true, member: memberView(registry.get(id)) });
    }

    /* Issue a single-use nonce to defeat replay. */
    case 'GET /api/nonce': {
      const nonce = nonceString(url.searchParams.get('prefix') || 'auth');
      unclaimed.set(nonce, { expires: Date.now() + NONCE_TTL });
      return sendJson(res, 200, { nonce, ttlMs: NONCE_TTL });
    }

    /* Verify a non-interactive Schnorr proof of knowledge. */
    case 'POST /api/auth/nizk': {
      const body = await readBody(req);
      try {
        const y = unhex(body.y);
        const t = unhex(body.proof.t);
        const s = unhex(body.proof.s);
        const message = String(body.message || '');

        if (!consumeNonce(message)) {
          logEvent('nizk', 'Rejected: unknown or already-used nonce', { message });
          return sendJson(res, 200, { ok: false, error: 'invalid or reused nonce' });
        }
        const ok = ZK.nizkVerify({ t, s, y }, message);
        const known = [...registry.values()].find((m) => m.y === y);
        logEvent('nizk', ok
          ? `ZKP verified${known ? ` — authenticated "${known.name}"` : ' — identity not in directory'}`
          : 'ZKP verification FAILED', { y: hex(y) });
        return sendJson(res, 200, {
          ok,
          identity: ok && known ? { id: known.id, name: known.name } : null,
          error: ok ? null : 'invalid proof'
        });
      } catch (e) {
        return sendJson(res, 200, { ok: false, error: 'malformed proof: ' + e.message });
      }
    }

    /* --- Interactive Schnorr: prover commits first. --- */
    case 'POST /api/auth/interactive/commit': {
      const body = await readBody(req);
      try {
        const y = unhex(body.y);
        const t = unhex(body.t);
        const sessionId = randId() + randId();
        const challenge = ZK.randomChallenge();
        sessions.set(sessionId, { y, t, challenge, expires: Date.now() + SESSION_TTL });
        logEvent('interactive', 'Commitment t = g^r received; challenge c issued', { sessionId });
        return sendJson(res, 200, { ok: true, sessionId, challenge: hex(challenge) });
      } catch (e) {
        return sendJson(res, 400, { ok: false, error: e.message });
      }
    }

    /* --- Interactive Schnorr: prover returns s = r + c*x. --- */
    case 'POST /api/auth/interactive/respond': {
      const body = await readBody(req);
      const s = sessions.get(body.sessionId);
      sessions.delete(body.sessionId);
      if (!s) return sendJson(res, 200, { ok: false, error: 'unknown or expired session' });
      if (s.expires < Date.now()) return sendJson(res, 200, { ok: false, error: 'session expired' });
      let ok = false;
      try {
        ok = ZK.schnorrVerify(s.y, s.challenge, unhex(body.s), s.t);
      } catch (e) { /* malformed */ }
      const known = [...registry.values()].find((m) => m.y === s.y);
      logEvent('interactive', ok
        ? `Handshake complete — "g^s == t * y^c" holds${known ? ` for "${known.name}"` : ''}`
        : 'Handshake FAILED — verification equation false');
      return sendJson(res, 200, {
        ok,
        identity: ok && known ? { id: known.id, name: known.name } : null,
        error: ok ? null : 'invalid proof'
      });
    }

    /* Verify an AOS ring signature (anonymous group authentication). */
    case 'POST /api/ring/verify': {
      const body = await readBody(req);
      try {
        const ring = body.ring.map(unhex);
        const c = body.signature.c.map(unhex);
        const z = body.signature.z.map(unhex);
        const message = String(body.message || '');

        if (!consumeNonce(message)) {
          logEvent('ring', 'Rejected: unknown or reused nonce', { message });
          return sendJson(res, 200, { ok: false, error: 'invalid or reused nonce' });
        }
        const ok = ZK.ringVerify(message, ring, { c, z });
        const names = [...registry.values()].filter((m) => ring.includes(m.y)).map((m) => m.name);
        logEvent('ring', ok
          ? `Ring signature valid — signer is ONE OF {${names.join(', ') || 'n/a'}}, identity HIDDEN`
          : 'Ring signature FAILED', { ringSize: ring.length });
        return sendJson(res, 200, {
          ok,
          anonymitySet: names,
          error: ok ? null : 'invalid ring signature'
        });
      } catch (e) {
        return sendJson(res, 200, { ok: false, error: 'malformed signature: ' + e.message });
      }
    }

    case 'GET /api/log':
      return sendJson(res, 200, { entries: auditLog.slice(0, 40) });

    default:
      return sendJson(res, 404, { ok: false, error: 'not found' });
  }
}

/* One-time nonces: claim exactly once. */
function consumeNonce(message) {
  if (unclaimed.has(message)) { unclaimed.delete(message); return true; }
  return false;
}

/* ------------------------------------------------------------------ *
 *  Server
 * ------------------------------------------------------------------ */
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));

  if (url.pathname.startsWith('/api/')) {
    handleApi(req, res, url).catch((e) => sendJson(res, 500, { ok: false, error: e.message }));
    return;
  }

  // Static assets.
  if (url.pathname === '/' || url.pathname === '/index.html') {
    return serveFile(res, PUBLIC_DIR, 'index.html');
  }
  if (url.pathname.startsWith('/lib/')) {
    return serveFile(res, LIB_DIR, url.pathname.slice('/lib/'.length));
  }
  return serveFile(res, PUBLIC_DIR, url.pathname.slice(1));
});

server.listen(PORT, () => {
  console.log('  \u250C\u2500 Zero-Knowledge Anonymous Authentication');
  console.log(`  \u2502  Server running:  http://localhost:${PORT}`);
  console.log(`  \u2502  Group:          RFC 3526 MODP Group 14 (2048-bit)`);
  console.log('  \u2514\u2500 Proofs:          Schnorr NIZK + interactive + AOS ring');
});

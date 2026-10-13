/*
 * End-to-end API test: boots server.js, then drives the verifier over HTTP
 * exactly like the browser does. Run with: node test/api.test.js
 */
'use strict';
const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const ZK = require('../lib/zk');

const PORT = 3999;
const BASE = 'http://127.0.0.1:' + PORT + '/api';
const hex = (x) => x.toString(16);
const unhex = (h) => BigInt('0x' + h);

let passed = 0;
const ok = (n) => { passed++; console.log('  \u2713 ' + n); };

const post = (p, body) => fetch(BASE + p, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
}).then((r) => r.json());
const get = (p) => fetch(BASE + p).then((r) => r.json());

async function waitForServer(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try { await get('/params'); return; } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  throw new Error('server did not start');
}

(async function main() {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore'
  });

  try {
    await waitForServer();
    console.log('Server booted on port ' + PORT);

    console.log('Group params + registry');
    {
      const p = await get('/params');
      assert.ok(p.p && p.q && p.g && p.pBits === 2048, 'params exposed');
      assert.deepStrictEqual((await get('/registry')).members, [], 'registry starts empty');
      ok('params + empty registry');
    }

    console.log('Registration');
    const alice = ZK.keygen();
    const bob = ZK.keygen();
    {
      const r = await post('/register', { name: 'alice', y: hex(alice.y) });
      assert.ok(r.ok && r.member.name === 'alice', 'alice registered');
      await post('/register', { name: 'bob', y: hex(bob.y) });
      const reg = await get('/registry');
      assert.strictEqual(reg.members.length, 2, 'two members');
      ok('public keys registered, secret x never sent');
    }

    console.log('Schnorr NIZK login');
    {
      const { nonce } = await get('/nonce?prefix=auth');
      const proof = ZK.nizkProve(alice.x, alice.y, nonce);
      const good = await post('/auth/nizk', { y: hex(alice.y), proof: { t: hex(proof.t), s: hex(proof.s) }, message: nonce });
      assert.ok(good.ok && good.identity.name === 'alice', 'valid proof accepted + identity resolved');

      const replay = await post('/auth/nizk', { y: hex(alice.y), proof: { t: hex(proof.t), s: hex(proof.s) }, message: nonce });
      assert.ok(!replay.ok, 'replayed nonce rejected');
      ok('NIZK accepted + replay blocked');
    }

    console.log('Interactive handshake');
    {
      const { r, t } = ZK.schnorrCommit();
      const c = await post('/auth/interactive/commit', { y: hex(bob.y), t: hex(t) });
      assert.ok(c.ok && c.challenge, 'commitment accepted, challenge issued');
      const s = ZK.schnorrRespond(r, unhex(c.challenge), bob.x);
      const fin = await post('/auth/interactive/respond', { sessionId: c.sessionId, s: hex(s) });
      assert.ok(fin.ok && fin.identity.name === 'bob', 'handshake verified');

      // Forged response must fail.
      const c2 = await post('/auth/interactive/commit', { y: hex(bob.y), t: hex(t) });
      const bad = ZK.mod(s + 1n, ZK.Q);
      const fin2 = await post('/auth/interactive/respond', { sessionId: c2.sessionId, s: hex(bad) });
      assert.ok(!fin2.ok, 'forged response rejected');
      ok('challenge/response verified + forgery rejected');
    }

    console.log('Ring signature anonymous auth');
    {
      const reg = await get('/registry');
      const ring = reg.members.map((m) => unhex(m.y));
      const { nonce } = await get('/nonce?prefix=ring');
      const sig = ZK.ringSign(nonce, ring, 0, alice.x); // sign as alice
      const v = await post('/ring/verify', {
        message: nonce, ring: reg.members.map((m) => m.y),
        signature: { c: sig.c.map(hex), z: sig.z.map(hex) }
      });
      assert.ok(v.ok, 'ring signature valid');
      assert.deepStrictEqual(v.anonymitySet.sort(), ['alice', 'bob'], 'verifier sees full anonymity set');

      const { nonce: nonce2 } = await get('/nonce?prefix=ring');
      const forged = ZK.ringSign(nonce2, ring, 0, ZK.keygen().x); // outsider secret
      const v2 = await post('/ring/verify', {
        message: nonce2, ring: reg.members.map((m) => m.y),
        signature: { c: forged.c.map(hex), z: forged.z.map(hex) }
      });
      assert.ok(!v2.ok, 'outsider forgery rejected');
      ok('anonymous auth valid + forgery rejected');
    }

    console.log('\nAll ' + passed + ' API test groups passed.');
  } finally {
    child.kill();
  }
})().catch((e) => { console.error(e); process.exit(1); });

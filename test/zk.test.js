/*
 * Self-contained test suite for lib/zk.js — run with `npm test`.
 * Exercises the Schnorr identification protocol, the Fiat-Shamir NIZK,
 * and the AOS ring signature, including negative (forgery) cases.
 */
const assert = require('assert');
const ZK = require('../lib/zk');

let passed = 0;
function ok(name) { passed++; console.log('  \u2713 ' + name); }

console.log('Group sanity');
{
  assert.strictEqual(ZK.P % 2n, 1n, 'p is odd');
  assert.strictEqual((ZK.P - 1n) % ZK.Q, 0n, 'q divides p-1');
  // g generates the order-q subgroup: g^q == 1 (mod p)
  assert.strictEqual(ZK.modPow(ZK.G, ZK.Q, ZK.P), 1n, 'g^q == 1');
  ok('group parameters consistent');
}

console.log('Keygen');
{
  const { x, y } = ZK.keygen();
  assert.ok(x > 0n && x < ZK.Q, 'x in range');
  assert.strictEqual(y, ZK.modPow(ZK.G, x, ZK.P), 'y = g^x');
  ok('keygen produces valid keypair');
}

console.log('Schnorr identification (interactive)');
{
  const { x, y } = ZK.keygen();
  const { r, t } = ZK.schnorrCommit();
  const c = ZK.randomChallenge();
  const s = ZK.schnorrRespond(r, c, x);
  assert.ok(ZK.schnorrVerify(y, c, s, t), 'honest proof verifies');

  // Wrong secret must fail.
  const bad = ZK.mod(s + 1n, ZK.Q);
  assert.ok(!ZK.schnorrVerify(y, c, bad, t), 'tampered response rejected');

  // Replayed response against a different challenge must fail.
  const c2 = ZK.randomChallenge();
  assert.ok(!ZK.schnorrVerify(y, c2, s, t), 'wrong challenge rejected');
  ok('completeness + soundness');
}

console.log('Schnorr NIZK (Fiat-Shamir)');
{
  const { x, y } = ZK.keygen();
  const msg = 'nonce:' + Date.now();
  const proof = ZK.nizkProve(x, y, msg);
  assert.ok(ZK.nizkVerify(proof, msg), 'valid proof verifies');
  assert.ok(!ZK.nizkVerify(proof, msg + 'x'), 'bound to message');
  assert.ok(!ZK.nizkVerify({ ...proof, s: ZK.mod(proof.s + 1n, ZK.Q) }, msg), 'tampered proof rejected');
  ok('completeness, binding + soundness');
}

console.log('AOS ring signature (anonymous authentication)');
{
  const members = [];
  for (let i = 0; i < 5; i++) members.push(ZK.keygen());
  const ring = members.map((m) => m.y);
  const msg = 'login-nonce-42';

  // Every member can sign; verifier learns nothing about which one.
  for (let idx = 0; idx < members.length; idx++) {
    const sig = ZK.ringSign(msg, ring, idx, members[idx].x);
    assert.ok(ZK.ringVerify(msg, ring, sig), 'signer ' + idx + ' verifies');
  }

  const sig = ZK.ringSign(msg, ring, 2, members[2].x);
  assert.ok(!ZK.ringVerify(msg + '!', ring, sig), 'signature bound to message');

  // A non-member cannot produce a valid signature for the ring.
  const outsider = ZK.keygen();
  const forged = ZK.ringSign(msg, ring, 2, outsider.x);
  assert.ok(!ZK.ringVerify(msg, ring, forged), 'outsider forgery rejected');

  // Corrupting any response breaks verification.
  const brokenC = { c: sig.c.slice(), z: sig.z.slice() };
  brokenC.c[0] = ZK.mod(brokenC.c[0] + 1n, ZK.Q);
  assert.ok(!ZK.ringVerify(msg, ring, brokenC), 'corrupted challenge rejected');

  ok('completeness, anonymity set + unforgeability');
}

console.log('\nAll ' + passed + ' test groups passed.');

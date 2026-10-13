/*
 * zk.js — Zero-Knowledge Proof primitives for anonymous authentication.
 *
 * Shared, dependency-free module usable in the browser (window.ZK) and in
 * Node.js (require('./lib/zk')). Everything is synchronous and deterministic.
 *
 * Implements:
 *   1. Schnorr identification protocol (interactive challenge/response)
 *   2. Schnorr NIZK proof of knowledge (Fiat-Shamir transform)
 *   3. AOS ring signature (1-out-of-n OR-proof) for anonymous group auth
 *
 * Group: RFC 3526 MODP Group 14 (2048-bit safe prime), generator g = 2,
 * subgroup order q = (p - 1) / 2.  All exponentiations happen mod p;
 * all secret scalars live in Z_q.
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.ZK = mod;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ *
   *  Minimal synchronous SHA-256 (FIPS 180-4)
   * ------------------------------------------------------------------ */
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(data) {
    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    const len = data.length;
    const bitLen = len * 8;
    const total = (((len + 9) + 63) >> 6) << 6;
    const buf = new Uint8Array(total);
    buf.set(data);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(bitLen / 4294967296));
    dv.setUint32(total - 4, bitLen >>> 0);

    const w = new Uint32Array(64);
    for (let off = 0; off < total; off += 64) {
      for (let j = 0; j < 16; j++) w[j] = dv.getUint32(off + j * 4);
      for (let j = 16; j < 64; j++) {
        const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }
      let a = h[0], b = h[1], c = h[2], d = h[3],
          e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let j = 0; j < 64; j++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[j] + w[j]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
      h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
    return out;
  }

  /* ------------------------------------------------------------------ *
   *  BigInt helpers
   * ------------------------------------------------------------------ */
  function bytesToBigInt(bytes) {
    let x = 0n;
    for (let i = 0; i < bytes.length; i++) x = (x << 8n) | BigInt(bytes[i]);
    return x;
  }

  function bigIntToBytes(x, len) {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function mod(a, m) { const r = a % m; return r >= 0n ? r : r + m; }

  function modPow(base, exp, m) {
    let r = 1n;
    base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % m;
      exp >>= 1n;
      base = (base * base) % m;
    }
    return r;
  }

  const HEX = '0123456789abcdef';
  function toHex(x) {
    let h = x.toString(16);
    return h;
  }
  function fromHex(h) { return BigInt('0x' + h); }

  /* ------------------------------------------------------------------ *
   *  System randomness
   * ------------------------------------------------------------------ */
  let nodeCrypto = null;
  function filler() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto &&
        typeof globalThis.crypto.getRandomValues === 'function') {
      return globalThis.crypto;
    }
    if (typeof self !== 'undefined' && self.crypto) return self.crypto;
    if (typeof require === 'function') {
      if (!nodeCrypto) nodeCrypto = require('crypto');
      if (nodeCrypto.webcrypto) return nodeCrypto.webcrypto;
      return {
        getRandomValues(b) { const r = nodeCrypto.randomBytes(b.length); b.set(r); return b; }
      };
    }
    throw new Error('No secure random source available');
  }

  function randomBytes(n) {
    const b = new Uint8Array(n);
    filler().getRandomValues(b);
    return b;
  }

  /* ------------------------------------------------------------------ *
   *  Group parameters (RFC 3526 MODP Group 14)
   * ------------------------------------------------------------------ */
  const P = BigInt(
    '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'
  );
  const G = 2n;
  const Q = (P - 1n) / 2n;          // subgroup order (safe prime => Q is prime)
  const PLEN = 256;                  // bytes needed to encode a group element
  const QLEN = 256;                  // bytes to encode a scalar

  const enc = (x) => bigIntToBytes(mod(x, P), PLEN);
  const encScalar = (x) => bigIntToBytes(mod(x, Q), QLEN);
  function encStr(s) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s);
    return Uint8Array.from(Buffer.from(s, 'utf8'));
  }

  function concat(arrays) {
    let n = 0;
    for (const a of arrays) n += a.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;
  }

  // Hash arbitrary labelled parts into a scalar in Z_q.
  function hashToScalar(parts) {
    return mod(bytesToBigInt(sha256(concat(parts))), Q);
  }

  function randomScalar() {
    // Uniform in [1, Q-1] via rejection sampling.
    for (let i = 0; i < 64; i++) {
      const x = bytesToBigInt(randomBytes(PLEN + 1)) % Q;
      if (x > 0n) return x;
    }
    return 1n;
  }

  /* ------------------------------------------------------------------ *
   *  1. Key generation
   * ------------------------------------------------------------------ */
  function keygen() {
    const x = randomScalar();
    const y = modPow(G, x, P);
    return { x, y };
  }

  /* ------------------------------------------------------------------ *
   *  2. Schnorr identification (interactive)
   * ------------------------------------------------------------------ */
  function schnorrCommit() {
    const r = randomScalar();
    return { r, t: modPow(G, r, P) };
  }

  function schnorrRespond(r, challenge, x) {
    return mod(r + mod(challenge, Q) * x, Q);
  }

  function schnorrVerify(y, challenge, s, t) {
    const lhs = modPow(G, mod(s, Q), P);
    const rhs = mod(t * modPow(y, mod(challenge, Q), P), P);
    return lhs === rhs;
  }

  function randomChallenge() {
    // 256-bit challenge as BigInt.
    return bytesToBigInt(randomBytes(32));
  }

  /* ------------------------------------------------------------------ *
   *  3. Schnorr NIZK proof of knowledge (Fiat-Shamir)
   * ------------------------------------------------------------------ */
  function nizkProve(x, y, message) {
    const { r, t } = schnorrCommit();
    const c = hashToScalar([enc(G), enc(y), enc(t), encStr('nizk|' + (message || ''))]);
    const s = schnorrRespond(r, c, x);
    return { t, s, y, c };
  }

  function nizkVerify(proof, message) {
    const { t, s, y } = proof;
    const c = hashToScalar([enc(G), enc(y), enc(t), encStr('nizk|' + (message || ''))]);
    return schnorrVerify(y, c, s, t);
  }

  /* ------------------------------------------------------------------ *
   *  4. AOS ring signature (1-out-of-n anonymous authentication)
   * ------------------------------------------------------------------ */
  function ringSign(message, ring, signerIndex, x) {
    const n = ring.length;
    if (signerIndex < 0 || signerIndex >= n) throw new Error('bad signerIndex');
    const r = randomScalar();
    const t = new Array(n);
    const c = new Array(n);
    const z = new Array(n);

    t[signerIndex] = modPow(G, r, P);
    for (let i = 0; i < n; i++) {
      if (i === signerIndex) continue;
      c[i] = hashToScalar([encStr('ring-sim|'), enc(ring[i]), randomBytes(32)]) % Q;
      if (c[i] === 0n) c[i] = 1n;
      z[i] = randomScalar();
      // t_i = g^{z_i} * y_i^{-c_i}
      const negC = mod(Q - c[i], Q);
      t[i] = mod(modPow(G, z[i], P) * modPow(ring[i], negC, P), P);
    }

    const parts = [encStr('ring|' + (message || ''))];
    for (const y of ring) parts.push(enc(y));
    for (const ti of t) parts.push(enc(ti));
    const cTotal = hashToScalar(parts);

    let sum = 0n;
    for (let i = 0; i < n; i++) if (i !== signerIndex) sum = mod(sum + c[i], Q);
    c[signerIndex] = mod(cTotal - sum, Q);
    z[signerIndex] = mod(r + c[signerIndex] * x, Q);

    return { c, z };
  }

  function ringVerify(message, ring, signature) {
    const { c, z } = signature;
    const n = ring.length;
    if (!c || !z || c.length !== n || z.length !== n) return false;
    const t = new Array(n);
    for (let i = 0; i < n; i++) {
      const negC = mod(Q - mod(c[i], Q), Q);
      t[i] = mod(modPow(G, mod(z[i], Q), P) * modPow(ring[i], negC, P), P);
    }
    const parts = [encStr('ring|' + (message || ''))];
    for (const y of ring) parts.push(enc(y));
    for (const ti of t) parts.push(enc(ti));
    const cTotal = hashToScalar(parts);
    let sum = 0n;
    for (const ci of c) sum = mod(sum + ci, Q);
    return sum === cTotal;
  }

  return {
    P, Q, G, PLEN, QLEN,
    sha256,
    bytesToBigInt, bigIntToBytes, mod, modPow,
    toHex, fromHex, randomScalar, randomBytes, hashToScalar,
    keygen,
    schnorrCommit, schnorrRespond, schnorrVerify, randomChallenge,
    nizkProve, nizkVerify,
    ringSign, ringVerify
  };
});

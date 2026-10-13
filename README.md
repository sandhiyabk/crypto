# ZK AnonAuth — Zero-Knowledge Anonymous Authentication

A full-stack web application demonstrating **zero-knowledge proof (ZKP) protocols
for anonymous authentication** in cryptography and networks.

The browser acts as the **prover**; a Node.js service acts as the **verifier /
authenticating network endpoint**. Secret keys are generated in the browser and
are **never transmitted**.

```
 ┌──────────────┐        proof (t, s)          ┌──────────────┐
 │   Browser    │  ─────────────────────────►  │  Verifier    │
 │  (prover)    │        nonce, challenge      │  (server)    │
 │  holds x     │  ◄─────────────────────────  │  holds y=g^x  │
 └──────────────┘                              └──────────────┘
        │                                             │
        └── only  y = g^x mod p  is ever registered ──┘
```

## Protocols implemented

| # | Protocol | Purpose | Zero-knowledge property |
|---|----------|---------|-------------------------|
| 1 | **Schnorr identification** (3-move Σ-protocol) | Challenge/response login | Reveals nothing about `x`; simulator exists for any challenge |
| 2 | **Schnorr NIZK** (Fiat–Shamir) | Non-interactive login | Proof bound to a single-use nonce (replay-safe) |
| 3 | **AOS ring signature** (1-out-of-n OR-proof) | Anonymous group authentication | Verifier learns *a* member signed, not *which* one |

- **Group:** RFC 3526 MODP Group 14 — a 2048-bit safe prime `p`, subgroup order
  `q = (p−1)/2`, generator `g = 2`.
- **Hashing:** SHA-256 (FIPS 180-4), implemented dependency-free so the same code
  runs byte-identically in the browser and Node.
- **Security rests on** the discrete-logarithm assumption.

## Run it

```bash
npm install     # no dependencies — safe to skip
npm start       # starts http://localhost:3000
```

Open <http://localhost:3000> and walk the tabs left to right:

1. **Identity & Keys** — generate a keypair, register the public key, and seed
   four demo members.
2. **Interactive Handshake** — step through commit → challenge → response.
3. **ZK Login (NIZK)** — one-message proof; replay of the same proof is rejected.
4. **Anonymous Group Auth** — sign as one member of a ring; the server validates
   the signature and reports the *anonymity set*, never the signer.
5. **The Math** — the equations behind each protocol.

## Tests

```bash
npm test              # crypto unit tests + end-to-end API tests
npm run test:crypto   # protocol completeness / soundness / anonymity
npm run test:api      # boots the server and drives it over HTTP
```

The crypto suite covers honest verification, tampered responses, wrong
challenges, message binding, outsider forgery, and ring anonymity.

## Project layout

```
crypto/
├─ server.js              # HTTP server: static host + verifier API
├─ lib/zk.js              # shared ZK crypto (browser + Node)
├─ public/
│  ├─ index.html          # UI
│  ├─ css/style.css
│  └─ js/app.js           # browser prover + UI logic
└─ test/
   ├─ zk.test.js          # crypto unit tests
   └─ api.test.js         # end-to-end HTTP protocol tests
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/params` | Group parameters `p, q, g` |
| `GET`  | `/api/registry` | Registered public keys |
| `POST` | `/api/register` | Register `{ name, y }` |
| `GET`  | `/api/nonce` | Issue a single-use nonce |
| `POST` | `/api/auth/nizk` | Verify a NIZK proof |
| `POST` | `/api/auth/interactive/commit` | Submit commitment `t`, get challenge `c` |
| `POST` | `/api/auth/interactive/respond` | Submit response `s` |
| `POST` | `/api/ring/verify` | Verify a ring signature |
| `GET`  | `/api/log` | Server audit log |

## How the math works

**Correctness** — Schnorr verification is
`g^s = g^(r + c·x) = g^r · (g^x)^c = t · y^c`.

**Special soundness** — two accepting transcripts `(t, c, s)` and `(t, c', s')`
with `c ≠ c'` yield `x = (s − s')/(c − c') mod q`.

**Zero-knowledge** — a simulator chooses `s` first and computes
`t = g^s · y^(−c)`; transcripts are identically distributed to real ones.

**Anonymity (ring signatures)** — for every non-signer index the pair
`(c_i, z_i)` is chosen uniformly at random, so the signature distribution is
independent of the real signer's index.

## Disclaimer

Educational demonstration. Do **not** use the protocol or parameters as-is to
protect production secrets.

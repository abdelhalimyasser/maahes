# Migration & operational runbooks

## 1. Pepper rotation (the runbook)

### Preparation

1. Generate the new secret and put it in your secret manager.
2. Roll the config **without** dropping the old secret:

```ts
const pwd = Password({
  pepper: {
    current: { id: "2026-a", secret: process.env.PASSWORD_PEPPER },   // new
    previous: [{ id: "2025-b", secret: process.env.OLD_PASSWORD_PEPPER }], // old, kept for a while
  },
});
```

3. Deploy and watch logs for `needsRehash` rates. Every login now
   re-peppers old-era hashes onto `current` via `verifyAndRehash`.

### During the window

- New hashes always use `current`; old-era hashes verify through the
  marker-routed `previous` secret.
- `pepperedVerifyPassword` remains for **unmarked legacy hashes**
  (pre-marker era): it tries current first, then previous, in order —
  that is the only path that costs one KDF per secret.

### Retirement

1. After the window (typically weeks — long enough that all active users
   have logged in), remove the `previous` entry.
2. Old markers then fail safely (`false`) — do not "upgrade" the
   database behind the library's back; let `verifyAndRehash` do it at
   login, where the plaintext exists.
3. Rotate the *current* secret the same way next time (it moves to
   `previous`).

### Ids matter

Marker ids must match ring ids. The legacy string form
(`pepper: "secret"`) derives a stable 8-hex id (SHA-256), so 1.x markers
still verify. When constructing an old-era module by hand, declare the
id explicitly so the marker routes correctly:

```ts
const era2025 = Password({ pepper: { current: { id: "2025-b", secret: OLD } } });
```

## 2. Algorithm migration (bcrypt/scrypt → argon2id)

Maahes detects the stored hash's algorithm on every verify, so a single
module can read any of the three:

```ts
const readers = {
  argon2: Password(),
  bcrypt: Password({ algorithm: "bcrypt" }),
  scrypt: Password({ algorithm: "scrypt" }),
};

async function login(stored, password) {
  const algo = detectHashAlgorithm(stored);          // pepper-aware
  const reader = readers[algo] ?? null;              // null → unsupported format
  if (!reader) return 500;                            // don't guess SHA-1/MD5
  if (!(await reader.verifyPassword(stored, password))) return 401;
  await updateHash(user.id, await target.rehashPassword(password)); // upgrade at login
}
```

`verifyAndRehash` absorbs the same transition automatically when the
configured algorithm differs from the stored one.

## 3. bcrypt `preHash` flip — NOT automatable

`preHash` changes what is hashed (SHA-256 of the password first). A
hash produced with `preHash: true` cannot be verified with
`preHash: false` and vice versa — there is no marker for it. The library
reports `valid: false` honestly; it will never guess. If you must flip:

1. Verify with a module carrying the old setting
   (`Password({ algorithm: "bcrypt", bcrypt: { preHash: old } })`).
2. Rehash with the new setting via `verifyAndRehash`-style logic in
   *your* code, since the two states are indistinguishable to Maahes.

## 4. Normalization change — NOT automatable

Switching `normalize: "none"` → `"nfkc"` (or back) changes the input
pre-hash. Same consequence and same two-module approach as §3.

## 5. Parameter bumps (argon2 memory/time, bcrypt rounds, scrypt cost)

Fully automatic: `needsRehash` compares driver parameters, and
`verifyAndRehash` rehashes on drift at login. No scripts, no downtime —
benchmark yearly and bump when hardware moved an order of magnitude
(see [security.md](security.md)).

## 6. CORS / headers without downtime

- CORS: `preset: "express"` reproduces npm `cors` behavior for a
  drop-in swap (see [cors.md](cors.md#4-migrating-from-the-npm-cors-package)).
- Headers: deploy `SecurityHeaders({ overwrite: false })` first to
  observe existing framework headers, then flip to `overwrite: true`
  once your own headers are aligned.
- Use `build({ secure: false })` locally (no HSTS) and let the runtime
  adapters derive the real context in production.
# Security guidelines

Operational guidance for Maahes deployments — informed by OWASP
(Password Storage Cheat Sheet), NIST SP 800-63B, RFC 9106 and RFC 6797.
Re-evaluate as those documents evolve.

Deeper reading: [security-model.md](security-model.md) (guarantees) ·
[threat-model.md](threat-model.md) (attacker-by-attacker).

## Configuration checklist

```ts
Password({
  algorithm: "argon2",                       // or bcrypt (interop) / scrypt (no natives)
  argon2: { memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 }, // ≈64 MiB; benchmark → 100–300 ms
  normalize: "nfkc",                         // fold confusables (opt-in)
  pepper: { current: { id: "2026-a", secret: process.env.PASSWORD_PEPPER } },
  policy: {
    minLength: 10, maxLength: 128, minDigits: 1, minSymbols: 1, minEntropy: 50,
    blockedPasswords: [/* top-N breach list */],
    enforceOnHash: true,                     // registration boundary only
  },
});
// bcrypt: saltRounds >= 12; enable preHash only if >72-byte inputs are possible
// scrypt:  cost = power of 2 (2**14 default) — N, r jointly set memory use

SecurityHeaders({
  preset: "default",                         // strict if you can live without cross-origin subresources
  remove: ["Server", "X-Powered-By"],        // fingerprinting
  overwrite: false,                          // during rollout; then true
});
```

- **Rolling upgrades**: benchmark yearly; bump parameters when the cost
  moves an order of magnitude — `verifyAndRehash` refreshes holders at
  login, no scripts.
- **Pepper rotation runbook**: keyring `current` + `previous`, retire
  `previous` after the login window — see
  [migration.md](migration.md#1-pepper-rotation-the-runbook).
- **Blocklist**: seed from a breach top-N (exact match is O(1) even at
  10⁵ entries).
- **Headers**: `httpsOnly` defaults keep HSTS off plain HTTP; `preload`
  fails fast unless its real preconditions hold. Never disable
  `nosniff`/`frameOptions` without a compensating control.
- **CSP**: start with a report-only policy, then enforce. The safe
  baseline is `SecurityHeaders({ csp: "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'" })`;
  the modern strict-dynamic pattern (`Csp({ preset: "strict" })`) needs
  a per-request nonce — see [csp.md](csp.md).

## Do / don't

| ✅ Do | ❌ Don't |
| --- | --- |
| Same 401 for unknown user & wrong password; verify against a dummy hash when the user is missing (timing) | Log passwords or hashes — log rule names, not values |
| Store full hash in `TEXT`/`VARCHAR(255)`; never truncate/transform | Store the pepper beside the hashes (same backup = no protection) |
| `verifyAndRehash` on every login | Double-hash or add custom "salt layers" — drivers already salt + constant-time compare correctly |
| Peer-review parameters yearly | Skip validation when `enforceOnHash: false` — you lose both layers |
| Serve `SecurityHeaders` on every route, including error pages | Verify SHA-1/MD5/unsalted legacy hashes with this library — use the [migration flow](password.md#7-flows) |
| Rely on CORS + real authn/authz server-side | Treat CORS as authentication ([cors.md](cors.md#security-notes)) |

## Known divergences (deliberate)

- **Permissive defaults** (`enforceOnHash: false`, `normalize: "none"`,
  no class minimums) so nothing is blocked out of the box — hardening is
  configuration, not code. `allowedScripts` defaults to `["Any"]`
  (1.2.0): the old `["Latin"]` default rejected legitimate non-Latin
  passwords; restrict explicitly if you need script control.
- `minEntropy` is a **heuristic** (length × char-class pool; sequences
  inflate it) — gate with it, never claim it as a strength meter.
- `maxLength: 128` code points is a DoS guard; align with your UX.
# Security guidelines

Operational guidance for Maahes deployments — informed by OWASP
(Password Storage Cheat Sheet), NIST SP 800-63B and RFC 9106.
Re-evaluate as those documents evolve.

## Configuration checklist

```ts
Password({
  algorithm: "argon2",                       // or bcrypt (interop) / scrypt (no natives)
  argon2: { memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 }, // ≈64 MiB; benchmark → 100–300 ms
  normalize: "nfkc",                         // fold confusables (opt-in)
  pepper: process.env.PASSWORD_PEPPER,       // env, never committed
  policy: {
    minLength: 10, maxLength: 128, minDigits: 1, minSymbols: 1, minEntropy: 50,
    blockedPasswords: [/* top-N breach list */],
    enforceOnHash: true,                     // registration boundary only
  },
});
// bcrypt: saltRounds >= 12; enable preHash only if >72-byte inputs are possible
// scrypt:  cost = power of 2 (2**14 default) — N, r jointly set memory use
```

- **Rolling upgrades**: benchmark yearly; bump parameters when the cost
  moves an order of magnitude — `verifyAndRehash` refreshes holders at
  login, no scripts.
- **Pepper rotation runbook** before the incident: dual-era modules
  (see [password.md §6](password.md#6-peppering--rotation)).
- **Blocklist**: seed from a breach top-N (exact match is O(1) even at
  10⁵ entries).

## Do / don't

| ✅ Do | ❌ Don't |
| --- | --- |
| Same 401 for unknown user & wrong password; verify against a dummy hash when the user is missing (timing) | Log passwords or hashes — log rule names, not values |
| Store full hash in `TEXT`/`VARCHAR(255)`; never truncate/transform | Store the pepper beside the hashes (same backup = no protection) |
| `verifyAndRehash` on every login | Double-hash or add custom "salt layers" — drivers already salt + constant-time compare correctly |
| Peer-review parameters yearly | Skip validation when `enforceOnHash: false` — you lose both layers |
| | Verify SHA-1/MD5/unsalted legacy hashes with this library — use the [migration flow](password.md#7-flows) |

## Threat model

| Threat | Mitigation |
| --- | --- |
| DB leak → offline cracking | memory-hard KDF + per-hash random salt + pepper |
| Rainbow tables | unique random salt per hash (PHC format) |
| Timing side channels | `timingSafeEqual` (scrypt); library-constant-time (argon2/bcrypt); dummy-hash login |
| Confusable characters | `normalize: "nfkc"` + `allowedScripts` |
| Common passwords | `blockedPasswords` + `minEntropy` + `customRules` |
| Stale parameters | `needsRehash` / `verifyAndRehash` |
| "Forgot the pepper" bugs | self-describing `$pepper$` marker |

## Known divergences (deliberate)

- **Permissive defaults** (`enforceOnHash: false`, `normalize: "none"`,
  no class minimums) so nothing is blocked out of the box — hardening is
  configuration, not code.
- `minEntropy` is a **heuristic** (length × char-class pool; sequences
  inflate it) — gate with it, never claim it as a strength meter.
- `maxLength: 128` code points is a DoS guard; align with your UX.
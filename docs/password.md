# `Password` module

> Module home: `src/password/` · Type reference: `src/password/types.ts`
> (all types are re-exported from the package root).

## 1. Overview

Hashing, verification, policy enforcement and peppering for passwords —
three algorithms, fail-fast config, Unicode-aware rules, and login-time
rehashing with zero migration scripts.

**Feature highlights**

- **Algorithms** — Argon2id (default), bcrypt, scrypt — full option
  surfaces validated at construction (`PasswordOptionsError`).
- **Peppering** — HMAC-SHA256 site secret with a self-describing
  `$pepper$` marker; `verifyPassword` applies the pepper automatically.
- **Policy** — lengths, character classes, entropy floor, Unicode script
  whitelist, blocklist, and user-defined `customRules`; optional
  `enforceOnHash` gating.
- **Upgrades** — `verifyAndRehash` refreshes outdated hashes at login;
  `needsRehash` flags them for tooling.
- **Extras** — NFKC normalization, code-point-aware lengths,
  `detectHashAlgorithm` for multi-algo migration.

## 2. Quick start

```ts
import Password, {
  detectHashAlgorithm, estimateEntropy, PasswordPolicyError, PasswordOptionsError,
} from "@maahes/core";

// Defaults: Argon2id, permissive policy.
const pwd = Password();
const hash = await pwd.hashPassword("Tr0ub4dor&3-G00d");

// Login with automatic rehashing of outdated hashes:
const { valid, newHash } = await pwd.verifyAndRehash(hash, "Tr0ub4dor&3-G00d");
if (valid && newHash) await persistHash(newHash);

detectHashAlgorithm(hash); // "argon2"
```

Hardened one-liner (see [security.md](security.md) for rationale):

```ts
const pwd = Password({
  algorithm: "argon2",
  argon2: { memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 },
  normalize: "nfkc",                       // fold confusables
  pepper: process.env.PASSWORD_PEPPER,     // site secret
  policy: {
    minLength: 10, minDigits: 1, minSymbols: 1, minEntropy: 50,
    blockedPasswords: ["password", "12345678"],
    customRules: [{ rule: "noSequential", test: (p) => !/(.)\1{2,}/.test(p) }],
    enforceOnHash: true,
  },
});
```

## 3. API reference

### Instance methods (`Password(input?) → PasswordModule`)

| Signature | Returns | Notes |
| --- | --- | --- |
| `hashPassword(password)` | `Promise<string>` | Policy-gated when `enforceOnHash` (throws `PasswordPolicyError`) |
| `verifyPassword(hash, password)` | `Promise<boolean>` | Pepper-aware (marker auto-applied); never throws on bad hashes |
| `pepperedHashPassword(password)` | `Promise<string>` | HMAC-pepper → hash → wrap in `$pepper$<id>$…`; needs pepper |
| `pepperedVerifyPassword(hash, password)` | `Promise<boolean>` | Marked ✓ and legacy unmarked hashes |
| `needsRehash(hash)` | `Promise<boolean>` | Params outdated? Pepper-aware; malformed → `true` |
| `rehashPassword(password)` | `Promise<string>` | No policy check — for already-accepted passwords |
| `verifyAndRehash(hash, password)` | `Promise<{valid, newHash?}>` | One-shot login; `newHash` only when outdated; preserves pepper format |
| `validatePassword(password)` | `{valid, violations[]}` | Non-throwing, reports all violations |

### Standalone exports

| Export | Description |
| --- | --- |
| `detectHashAlgorithm(hash)` | `"argon2" / "bcrypt" / "scrypt" / null` — pepper-aware |
| `isPepperedHash(hash)` / `stripPepperMarker(hash)` | marker tests / unwrap |
| `estimateEntropy(password)` | heuristic bits (`codePointLength × log2(observedPool)`) |
| `validatePassword(pw, resolvedPolicy)` | low-level pure validator (needs all policy fields) |
| `DEFAULT_PASSWORD_CONFIG` | canonical defaults (introspection / tooling) |
| `PasswordOptionsError` / `PasswordPolicyError` | see [errors](#7-errors) |

### Types

```ts
interface PasswordConfig {
  algorithm?: "argon2" | "bcrypt" | "scrypt";   // default "argon2"
  pepper?: string;                               // fallback: PASSWORD_PEPPER env
  normalize?: "none" | "nfkc";                  // default "none"
  argon2?: Argon2Options;  bcrypt?: BcryptOptions;  scrypt?: ScryptOptions;
  policy?: PasswordPolicyOptions;
}
```

See `src/password/types.ts` for `Argon2Options`, `BcryptOptions`,
`ScryptOptions`, `PasswordPolicyOptions`, `CustomPasswordRule`,
`PolicyResult`, `VerifyResult`, `PasswordModule`.

## 4. Algorithms & configuration

| | Argon2id (default) | bcrypt | scrypt |
| --- | --- | --- | --- |
| Why | new systems (RFC 9106, OWASP pick) | legacy interop | zero native deps (`node:crypto`) |
| Costs | `memoryCost` KiB, `timeCost` iter. | `saltRounds` (2^rounds) | `cost` N (power of 2), `blockSize` r |
| Input limit | none | **72 bytes** → `preHash` fixes | none |
| Compare | library internal | library internal | `timingSafeEqual` |

Defaults (`DEFAULT_PASSWORD_CONFIG`, deep-merged per module):

```ts
argon2: { memoryCost: 2**16, timeCost: 3, parallelism: 1, hashLength: 32, saltLength: 16, version: 0x13 }
bcrypt: { saltRounds: 12, preHash: false }
scrypt: { cost: 2**14, blockSize: 8, parallelization: 1, keyLength: 64, saltLength: 16 }
```

Examples:

```ts
const argon = Password({ argon2: { memoryCost: 2 ** 16, timeCost: 3 } });
const bc    = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 12, preHash: true } });
const sc    = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 14 } });
```

**Validation (throws `PasswordOptionsError` at construction):**

| Option | Rule | Option | Rule |
| --- | --- | --- | --- |
| argon2 memoryCost | ≥ 8·parallelism | bcrypt saltRounds | integer 4..31 |
| argon2 timeCost / parallelism | ≥ 1 | bcrypt preHash | boolean |
| argon2 hashLength / saltLength | ≥ 4 / ≥ 8 | scrypt cost | power of 2, ≥ 2 |
| argon2 version | 0x10 or 0x13 | scrypt blockSize / parallelization / keyLength | ≥ 1 |
| | | scrypt saltLength | ≥ 8 |
| | | scrypt maxmem | ≥ 128·cost·blockSize·2 |

```ts
try { Password({ scrypt: { cost: 1000 } }) } catch (e) { /* "scrypt.cost must be a power of two >= 2" */ }
```

**bcrypt `preHash`** removes the 72-byte truncation
(`"a".repeat(72) + "tail"` no longer equals `"a".repeat(100)`), but those
hashes are **not portable** to standard bcrypt stacks — enable only when
you own the whole system.

**Dev/test speed:** lower costs — `argon2: { memoryCost: 2**14, timeCost: 1 }`,
`bcrypt: { saltRounds: 4 }`, `scrypt: { cost: 2**10 }`.

## 5. Policy

Rules run in order; `validatePassword` reports **every** violation:

| rule id | option | default |
| --- | --- | --- |
| `minLength`/`maxLength` | code points (emoji = 1) | 8 / 128 |
| `whitespace` | `blockWhitespace` | true |
| `minUppercase` / `minLowercase` / `minDigits` / `minSymbols` | class counts (Unicode-aware) | 0 (off) |
| `minEntropy` | `estimateEntropy` bits | 0 (off) |
| `allowedScripts` | `"Latin"|"Arabic"|"Cyrillic"|"Greek"|"Han"|"Any"` — letters only; digits/symbols are script-agnostic | `["Latin"]` |
| `blockedPasswords` | exact, case-insensitive, O(1) `Set` | `[]` |
| *custom* | `customRules` | `[]` |

Two enforcement surfaces — pick per boundary:

```ts
// Signup form: report everything.
const { valid, violations } = pwd.validatePassword(candidate);
// Hash boundary: throw instead.
const pwd = Password({ policy: { minLength: 10, enforceOnHash: true } });
await pwd.hashPassword("weak"); // throws PasswordPolicyError(err.violations)
```

**Custom rules** — `test` returns `true` = satisfied; second arg is the
fully-resolved policy:

```ts
customRules: [
  { rule: "noSequential", test: (p) => !/(.)\1{2,}/.test(p) },
  {
    rule: "notAnOldPassword", message: "Must differ from previous passwords",
    test: (p, policy) => !policy.blockedPasswords.some((b) => p.includes(b)),
  },
],
```

**NFKC normalization** (`normalize: "nfkc"`) folds confusables before
validation and hashing:

```ts
const p = Password({ normalize: "nfkc", policy: { minLength: 8, enforceOnHash: true } });
await p.hashPassword("ｐａｓｓｗｏｒｄ１２３");          // folds to "password123" ✓
await p.verifyPassword(hash, "password123");             // true
```

## 6. Peppering & rotation

```ts
const pwd = Password({ pepper: process.env.PASSWORD_PEPPER }); // env fallback ✓

const hash = await pwd.pepperedHashPassword("my-password");
// $pepper$<sha256(pepper)→8 hex>$argon2id$...
await pwd.verifyPassword(hash, "my-password");   // true — marker auto-applied
await legacyPwd.verifyPassword(hash, "my-password"); // false — wrong pepper
```

- **Unmarked legacy hashes** (pre-marker era): verify with
  `pepperedVerifyPassword`.
- **Rotation**: during the window, keep a module per era —
  `current` (new secret) + `previous` (old secret); upgrade on login:

```ts
const current = Password({ pepper: NEW });
const previous = Password({ pepper: OLD });

async function rotate(stored, password) {
  if (await current.verifyPassword(stored, password)) return;
  if (await previous.verifyPassword(stored, password)) {
    await persist(current.pepperedHashPassword(password)); // upgrade on login
  }
}
```

## 7. Flows

**Register** (policy at the boundary):

```ts
try { const hash = await pwd.hashPassword(body.password); await save(user, hash); }
catch (err) { if (err instanceof PasswordPolicyError) return 400(err.violations); throw err; }
```

**Login** (verify + upgrade, one call):

```ts
const { valid, newHash } = await pwd.verifyAndRehash(stored, password);
if (!valid) return 401;                        // same body for "no user" — no enumeration
if (newHash) await updateHash(user.id, newHash); // silent parameter upgrade
```

**Migrate a legacy store** — detect → verify with matching module → upgrade:

```ts
const readers = { argon2: Password(), bcrypt: Password({ algorithm: "bcrypt" }), scrypt: Password({ algorithm: "scrypt" }) };

async function login(stored, password) {
  const algo = detectHashAlgorithm(stored);
  const reader = readers[algo];                                   // null → unsupported (SHA-1/etc.)
  if (!reader) return 500;
  if (!(await reader.verifyPassword(stored, password))) return 401;
  await updateHash(user.id, await currentPwd.rehashPassword(password)); // upgrade to target algo
}
```

Rehashable on login only — **you cannot rehash without the plaintext**;
parameter bumps are absorbed automatically by `verifyAndRehash`.

## 8. Errors

| Error | Where | Carries |
| --- | --- | --- |
| `Error` | construction: bad input / unknown algo; peppered op without pepper | message |
| `PasswordOptionsError` | construction: option out of range | message naming option + range |
| `PasswordPolicyError` | `hashPassword`/`pepperedHashPassword` with `enforceOnHash` | `.violations: {rule,message}[]` |

Verification (`verifyPassword`, `pepperedVerifyPassword`, `verifyAndRehash`)
never throws on malformed hashes.

## 9. Run it

```bash
node examples/registration-login.mjs   # flows + upgrade
node examples/custom-policy.mjs        # strict policy, custom rules, NFKC
node examples/pepper-rotation.mjs      # markers, dual-verify rotation
node examples/migration-legacy.mjs     # bcrypt store → argon2
# works identically with `bun`
```
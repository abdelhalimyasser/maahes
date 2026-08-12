# Getting started

Everything you need before reading the module docs.

## Install

```bash
npm install @maahes/core   # or: bun add @maahes/core
```

| Runtime | Version | Verified by |
| --- | --- | --- |
| Node.js | ≥ 18 | `npm run smoke:node` |
| Bun | ≥ 1.x | `npm run smoke:bun` |

Artifacts: `dist/index.js` (ESM), `dist/index.cjs` (CJS), `dist/index.d.ts`
(TypeScript). Native deps (`argon2`, `bcrypt`) ship prebuilt binaries —
no platform setup.

## Quick start

```ts
import Password from "@maahes/core";

const pwd = Password();                                  // Argon2id, defaults
const hash = await pwd.hashPassword("S3cure!Pass-2024"); // signup
const ok   = await pwd.verifyPassword(hash, "S3cure!Pass-2024"); // login → true
```

```js
// CommonJS works identically:
const { Password } = require("@maahes/core");
```

## Conventions used by every module

**1. Factory + immutable instance.** Create once at boot, share everywhere
(thread-safe). `Password(input)` accepts:

```ts
Password();                          // all defaults
Password({ algorithm: "bcrypt" });   // object → deep-merged over defaults
Password('{"algorithm":"scrypt"}');  // inline JSON
Password("./password.config.json");  // file path ({"password": {...}} wrapper optional)
```

Every omitted field falls back to `DEFAULT_PASSWORD_CONFIG` (exported for
introspection). Nested objects merge field-by-field; arrays/primitives replace.

**2. Errors are structured and catchable.**

| Error | When | Example trigger |
| --- | --- | --- |
| `Error` | bad input / unknown algorithm / missing pepper | `Password({ algorithm: "md5" })` |
| `PasswordOptionsError` | option out of range, at construction | `Password({ bcrypt: { saltRounds: 99 } })` |
| `PasswordPolicyError` | policy violated with `enforceOnHash: true`; has `.violations` | `await pwd.hashPassword("short")` |

**3. Verification never throws.** Wrong password, corrupt/foreign hash →
`false`. Only peppered operations without a configured pepper throw (that
is a config bug).

```ts
const ok = await pwd.verifyPassword(maybeCorruptHash, input); // safe in try/catch-free login code
```

**4. Stored hashes are self-describing.** Parameters are embedded, so
`needsRehash`, re-verification and algorithm detection keep working after
config changes:

| Algorithm | Format |
| --- | --- |
| argon2 | `$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>` |
| bcrypt | `$2b$12$<salt><hash>` |
| scrypt | `$scrypt$N=16384$r=8$p=1$<salt>$<hash>` |
| peppered | `$pepper$<8-hex-id>$<any of the above>` |

## Next steps

- [password.md](password.md) — the shipped module
- [security.md](security.md) — production hardening
- [examples](../examples/) — `node examples/registration-login.mjs`
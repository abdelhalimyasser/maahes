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
import Password, { Cors, SecurityHeaders } from "@maahes/core";

const pwd = Password();                                  // Argon2id, defaults
const hash = await pwd.hashPassword("S3cure!Pass-2024"); // signup
const ok   = await pwd.verifyPassword(hash, "S3cure!Pass-2024"); // login → true

app.use(Cors({ origin: ["https://app.example.com"] }).middleware());
app.use(SecurityHeaders({ preset: "default" }).middleware());
```

```js
// CommonJS works identically:
const { Password } = require("@maahes/core");
```

## Conventions used by every module

**1. Factory + immutable instance.** Create once at boot, share everywhere
(thread-safe). Every factory — `Password`, `Cors`, `SecurityHeaders` —
accepts:

```ts
Password();                          // all defaults
Password({ algorithm: "bcrypt" });   // object → deep-merged over defaults
Password('{"algorithm":"scrypt"}');  // inline JSON
Password("./password.config.json");  // file path ({"password": {...}} wrapper optional)
```

Every omitted field falls back to the module's `DEFAULT_*_CONFIG`
(exported for introspection). Nested objects merge field-by-field;
arrays/primitives replace. See [configuration.md](configuration.md).

**2. Errors are structured and catchable** — every module error extends
the shared `MaahesError` base (option errors extend `MaahesOptionsError`):

| Error | When | Example trigger |
| --- | --- | --- |
| `MaahesOptionsError` subclasses (`PasswordOptionsError`, `CorsOptionsError`, `SecurityHeadersOptionsError`) | option out of range, at construction | `Password({ bcrypt: { saltRounds: 99 } })` |
| `PasswordPolicyError` | policy violated with `enforceOnHash: true`; has `.violations` | `await pwd.hashPassword("short")` |
| `Error` | bad input / unknown algorithm / missing pepper | `Password({ algorithm: "md5" })` |

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
| peppered | `$pepper$<id>$<any of the above>` — the id routes to the right secret in the keyring |

## Next steps

- [configuration.md](configuration.md) — shared config contract
- [password.md](password.md) — hashing, policy, peppering
- [cors.md](cors.md) — cross-origin rules
- [headers.md](headers.md) — security headers on every response
- [security.md](security.md) — production hardening
- [examples](../examples/) — `node examples/registration-login.mjs`
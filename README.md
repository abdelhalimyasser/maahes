# Maahes

**Maahes** is a security toolkit for **Node.js ≥ 18** and **Bun**, shipped
as ESM + CJS with TypeScript declarations. It gives application developers
battle-tested security primitives with sane defaults, a zero-surprise API
and first-class documentation.

The first shipped module is **`Password`** — a complete password-hashing
and policy toolkit:

- **Three algorithms** — Argon2id (default), bcrypt and scrypt — with the
  full option surface of each, validated at construction time.
- **Peppering** — HMAC-SHA256 site-secret mixing with a self-describing
  `$pepper$` marker; rotation-ready, immune to "forgot to pepper" bugs.
- **Policy engine** — lengths, character-class minimums, Unicode script
  whitelists, blocklists, entropy floors and fully **custom rules**.
- **Login-time rehashing** — `verifyAndRehash` upgrades outdated hashes
  the moment a user logs in; no migration scripts required.
- **OWASP-aligned extras** — NFKC normalization, code-point-aware
  validation, constant-time verification, fail-fast configuration.

More modules (CORS, CSRF, CSP, XSS, headers, rate limiting, …) are planned.

---

## Install

```bash
npm install @maahes/core
```

Works out of the box on **Node.js** and **Bun** (no transpilers, no
platform-specific setup — `argon2` and `bcrypt` ship prebuilt binaries):

| Runtime | Version | Verified |
| --- | --- | --- |
| Node.js | ≥ 18 | ✅ `npm run smoke:node` |
| Bun | ≥ 1.x | ✅ `npm run smoke:bun` |

## Quick start

```ts
import Password from "@maahes/core";

const pwd = Password(); // Argon2id with defaults - that's all it takes

// registration
const hash = await pwd.hashPassword("Tr0ub4dor&3-G00d");
await storeHash(hash);

// login
const stored = await loadHash();
const ok = await pwd.verifyPassword(stored, "Tr0ub4dor&3-G00d");
```

Hardened setup, one object away:

```ts
import Password from "@maahes/core";

const pwd = Password({
  algorithm: "argon2",
  argon2: { memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 },
  normalize: "nfkc",
  pepper: process.env.PASSWORD_PEPPER,
  policy: {
    minLength: 10,
    minUppercase: 1,
    minLowercase: 1,
    minDigits: 1,
    minSymbols: 1,
    minEntropy: 40,
    allowedScripts: ["Latin"],
    blockedPasswords: ["password", "12345678", "qwerty123"],
    customRules: [
      { rule: "noSequential", test: (p) => !/(.)\1{2,}/.test(p) },
    ],
    enforceOnHash: true,
  },
});

const hash = await pwd.hashPassword("Signup!Password1"); // throws if policy violated
```

## Modules

| Module | Status | Docs |
| --- | --- | --- |
| `Password` | ✅ shipped | [Getting started](docs/getting-started.md) · [Module reference](docs/password.md) |
| `Cors` | ✅ shipped | [Module reference](docs/cors.md) · [Examples](examples/) |
| CSRF / CSP / XSS / headers / rate limiting / secrets / hashing / encryption / audit | 🚧 planned | — |

## Quick look at `Cors`

```ts
import { Cors } from "@maahes/core";

const cors = Cors({
  origin: ["https://app.example.com", "https://*.example.com"],
  credentials: true,
});

app.use(cors.middleware());            // Express / Connect
// or raw node:  http.createServer(cors.middleware())
// or fetch:     server.fetch = cors.fetchHandler(route)
```

Origin globs, per-origin credentials, Private Network Access, `Vary`
merging and Express-compatible presets — see [docs/cors.md](docs/cors.md).

## Documentation

- [docs/index.md](docs/index.md) — hub + module index
- [Getting started](docs/getting-started.md) — install, runtimes, conventions, errors
- [`Password` module reference](docs/password.md) — API, algorithms, policy, peppering, flows
- [`Cors` module reference](docs/cors.md) — API, configs, presets, flows
- [Security guidelines](docs/security.md) — hardening checklist, threat model
- [Examples](examples/) — runnable end-to-end scripts (Node and Bun)

New modules will each get a `<module>.md` under `docs/` following the
same layout (see the hub for the roadmap).

## Development

```bash
bun test            # 178 unit + integration tests
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/ (ESM + CJS + .d.ts)
npm run smoke:node  # end-to-end checks against dist/ on Node.js
npm run smoke:bun   # end-to-end checks against dist/ on Bun
```

## License

MIT © Abdelhalim Yasser
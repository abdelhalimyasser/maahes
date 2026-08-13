# Maahes

**Maahes** is a security toolkit for **Node.js ≥ 18** and **Bun**, shipped
as ESM + CJS with TypeScript declarations. It gives application developers
battle-tested security primitives with sane defaults, deterministic
output and first-class documentation.

## Modules

| Module | Status | What it does |
| --- | --- | --- |
| [`Password`](docs/password.md) | ✅ 1.2.0 | Argon2id / bcrypt / scrypt hashing, Unicode-aware policy engine, keyring peppering with rotation |
| [`Cors`](docs/cors.md) | ✅ 1.1.0 | Origin rules & globs, per-origin credentials, PNA, Express/node/fetch adapters, `Vary` merging |
| [`SecurityHeaders`](docs/headers.md) | ✅ 1.2.0 | Deterministic header engine with presets, HSTS semantics, middleware + fetch adapters |
| [`Csp`](docs/csp.md) | ✅ 1.3.0 | Deterministic CSP engine: presets, nonces, report-only, strict parser, headers integration |
| CSRF · XSS · hashing · encryption · rate limiting · secrets · audit | 🚧 planned | each ships with the same contracts (see [roadmap](docs/index.md)) |

```ts
import Password, { Cors, SecurityHeaders, Csp } from "@maahes/core";

// Passwords
const pwd = Password();                          // Argon2id, sane defaults
const hash = await pwd.hashPassword("Tr0ub4dor&3-G00d");

// Responses
app.use(Cors({ origin: ["https://app.example.com"] }).middleware());
app.use(SecurityHeaders({ preset: "strict" }).middleware());

// Content Security Policy — static via SecurityHeaders, or nonce-based per request:
app.use(SecurityHeaders({ csp: "default-src 'self'" }).middleware());
const csp = Csp({ preset: "strict" });           // needs a nonce at build time
```

## Install

```bash
npm install @maahes/core
```

Works out of the box on **Node.js** and **Bun** — no transpilers, no
platform-specific setup (native `argon2` ships prebuilt binaries):

| Runtime | Version | Verified |
| --- | --- | --- |
| Node.js | ≥ 18 | ✅ `npm run smoke:node` |
| Bun | ≥ 1.x | ✅ `npm run smoke:bun` |

## Highlights

- **Deterministic engines.** Identical config + context → byte-identical
  output, fixed ordering, pure functions. Testable, diffable, cacheable.
- **Fail-fast configuration.** Option errors throw
  `MaahesOptionsError` subclasses at construction — at boot, never in a
  request handler. Verification never throws on hostile input: it fails
  `false` safely.
- **Keyring peppering.** `$pepper$` markers carry the secret's id, so
  rotation is a config change (new secret in `current`, old in
  `previous`) and old hashes keep verifying until re-peppered at login.
- **DoS-capped verification.** Cost parameters embedded in stored hashes
  are bounded before any KDF work — a hostile database row can't force
  unbounded CPU or memory.
- **Thin, honest adapters.** Middleware/fetch wrappers derive the secure
  context from TLS evidence, never `X-Forwarded-Proto`; they always call
  `next()` and never swallow downstream errors.
- **Hardened defaults.** HSTS only on secure contexts with `preload`
  preconditions enforced, credentials never paired with a wildcard,
  CRLF/splitting impossible by construction.

## Documentation

- [docs/index.md](docs/index.md) — hub + module index
- [Getting started](docs/getting-started.md) — install, runtimes, conventions, errors
- [Configuration](docs/configuration.md) — the shared config contract
- [`Password`](docs/password.md) · [`Cors`](docs/cors.md) · [`SecurityHeaders`](docs/headers.md) · [`Csp`](docs/csp.md)
- [Security guidelines](docs/security.md) — hardening checklist
- [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md)
- [Migration runbooks](docs/migration.md) — pepper rotation, algorithm upgrades
- [FAQ](docs/faq.md) — deliberate decisions and common questions
- [Examples](examples/) — runnable end-to-end scripts (Node and Bun)

## Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md) — process and ground rules
- [docs/contributing.md](docs/contributing.md) — the engineering bar
- [SECURITY.md](SECURITY.md) — private vulnerability reporting
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards

## Development

```bash
bun test            # 356 unit + integration tests (4 modules, incl. adversarial suites)
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/ (ESM + CJS + .d.ts)
npm run smoke:node  # end-to-end checks against dist/ on Node.js
npm run smoke:bun   # end-to-end checks against dist/ on Bun
```

## License

MIT © Abdelhalim Yasser
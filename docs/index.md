# Maahes Documentation

Documentation hub for the Maahes security toolkit. Every doc is written
so a reader can copy-paste the snippets into a real app — all of them are
verified to run on **Node.js ≥ 18** and **Bun** (the smoke script runs
the whole surface on both).

## How this documentation is organized

```
docs/
  index.md            ← you are here: navigation + module index
  getting-started.md  ← install, runtimes, quick start, conventions, errors
  configuration.md    ← the shared config contract (all modules)
  password.md         ← Password: API, configs, policy, peppering, flows
  cors.md             ← Cors: API, configs, presets, flows, security notes
  headers.md          ← SecurityHeaders: API, presets, adapters
  security.md         ← operational hardening checklist
  security-model.md   ← design guarantees, module by module
  threat-model.md     ← attacker-by-attacker analysis
  migration.md        ← pepper rotation & algorithm migration runbooks
  testing.md          ← how Maahes is tested + testing your config
  faq.md              ← common questions and deliberate decisions
  contributing.md     ← engineering bar for new code
examples/             ← runnable end-to-end scripts (Node + Bun)
```

## Module index

| Module | Status | Docs | Runtime |
| --- | --- | --- | --- |
| `Password` — hashing + policy + peppering (Argon2id / bcrypt / scrypt) | ✅ 1.2.0 | [password.md](password.md) · [examples](../examples/) | Node & Bun |
| `Cors` — origin rules, per-origin credentials, PNA, Express + node + fetch adapters | ✅ 1.1.0 | [cors.md](cors.md) · [examples](../examples/) | Node & Bun |
| `SecurityHeaders` — deterministic header engine, presets, middleware + fetch adapters | ✅ 1.2.0 | [headers.md](headers.md) · [examples](../examples/) | Node & Bun |
| CSRF, CSP, XSS, hashing, encryption, rate limiting, secrets, audit | 🚧 planned | — | — |

Upcoming modules follow the same contract: deterministic pure engine,
fail-fast config, adversarial tests, examples, docs.

## Start here

- New to Maahes → [getting-started.md](getting-started.md)
- Building a password system → [password.md](password.md)
- Opening your API to the web → [cors.md](cors.md)
- Hardening every response → [headers.md](headers.md)
- Hardening production → [security.md](security.md)
- What the toolkit does and doesn't stop → [threat-model.md](threat-model.md)
- See it run → `node examples/registration-login.mjs`

Also: [README](../README.md) (landing) · [CHANGELOG](../CHANGELOG.md)
# Maahes Documentation

Documentation hub for the Maahes security toolkit. Every doc is written
so a reader can copy-paste the snippets into a real app — all of them are
verified to run on **Node.js ≥ 18** and **Bun** (see
[Rechecking](../scripts/smoke.mjs) in `package.json`).

## How this documentation is organized

```
docs/
  index.md            ← you are here: navigation + module index
  getting-started.md  ← install, runtimes, quick start, conventions, errors
  cors.md             ← the CORS module: API, configs, presets, flows
  password.md         ← the Password module: API, configs, policy, peppering, flows
  security.md         ← hardening checklist, threat model, do's / don'ts
examples/             ← runnable end-to-end scripts (Node + Bun)
```

One file per module keeps the tree flat and makes room for the upcoming
modules: `csrf.md`, `csp.md`, `xss.md`, `headers.md`, `hashing.md`,
`encryption.md`, `rate-limit.md`, `secrets.md`, ... — each will follow
the same layout:

1. **Overview** — what it does and when to use it
2. **Quick start** — minimal working snippet
3. **API** — every export in a table, with signatures
4. **Configuration** — option tables with defaults and validation
5. **Guides** — the 2–3 real-world flows that matter
6. **Examples** — links into `examples/`

## Module index

| Module | Status | Docs | Runtime |
| --- | --- | --- | --- |
| `Password` — hashing + policy + peppering (Argon2id / bcrypt / scrypt) | ✅ 1.0.0 | [password.md](password.md) · [examples](../examples/) | Node & Bun |
| `Cors` — origin rules, per-origin credentials, PNA, Express + node + fetch adapters | ✅ 1.1.0 | [cors.md](cors.md) · [examples](../examples/) | Node & Bun |
| CSRF, CSP, XSS, headers, hashing, encryption, rate limiting, secrets, audit | 🚧 planned | — | — |

## Start here

- New to Maahes → [getting-started.md](getting-started.md)
- Building a password system → [password.md](password.md)
- Opening your API to the web → [cors.md](cors.md)
- Hardening production → [security.md](security.md)
- See it run → `node examples/registration-login.mjs`

Also: [README](../README.md) (landing) · [CHANGELOG](../CHANGELOG.md)
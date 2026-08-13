# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-08-13

### Added

- **SecurityHeaders module** (`SecurityHeaders()` factory, exported from
  the package root):
  - Deterministic engine: fixed emission order (`KNOWN_HEADER_ORDER`),
    sorted extras, case-insensitive `remove`, `overwrite` semantics —
    identical config + context → byte-identical output.
  - Presets `minimal` / `default` / `strict`, deep-merged with user
    options; `DEFAULT_HEADERS_CONFIG` exported for introspection.
  - Never emits `Content-Security-Policy` (reserved slot for the
    planned csp module).
  - HSTS with secure-context semantics (`httpsOnly: true` default),
    RFC 6797 §6.1 `maxAge` cap, and fail-fast `preload` preconditions.
  - Construction-time validation: RFC 7230 header-name tokens, control
    characters (CRLF/splitting) rejected in values, remove/extra and
    engine-owned-header conflicts (`SecurityHeadersOptionsError`).
  - Connect/Express middleware and Web-standard `fetchHandler` adapters:
    secure context from TLS socket / `req.secure` / `https://` URL
    (never `X-Forwarded-Proto`), always call `next()`, downstream errors
    always propagate.
  - Config from object, JSON string, or JSON file (`{"headers": …}`
    unwrapped).
- **Password hardening**:
  - Pepper **keyring** (`current` + `previous`) — rotation is now a
    config change; marked hashes route to the exact secret by id.
  - Verify-time DoS caps: stored-hash cost parameters bounded before any
    KDF work (argon2 ≤ 2²⁰ KiB / 32 / 16, scrypt ≤ 2¹⁸ / 16 / 8,
    bcrypt rounds ≤ 31, hash/salt length limits); over-cap hashes
    verify `false` and report `needsRehash: true`.
  - `verifyAndRehash` re-peppers rotated hashes onto the **current**
    secret (previous behavior reused the old secret); replacement never
    produced when verification fails.
  - Auto algorithm detection in `verifyPassword` / `needsRehash` /
    `verifyAndRehash` (per-hash driver selection).
  - All three driver option sets validated at construction, not only the
    active algorithm's.
  - Default `allowedScripts` changed `["Latin"]` → `["Any"]`: the old
    default silently rejected legitimate non-Latin passwords.
- **Shared error base**: `MaahesError` / `MaahesOptionsError`
  (`PasswordOptionsError`, `CorsOptionsError`,
  `SecurityHeadersOptionsError` extend them; `PasswordPolicyError`
  extends `MaahesError`).
- **Adversarial test suites**: password (127 tests), cors (107 tests),
  headers (71 tests) — hostile inputs, fail-closed paths, purity under
  frozen inputs, secret-leak assertions (305 total).
- **Examples**: `headers-server.mjs`, `headers-fetch.mjs`, rewritten
  `pepper-rotation.mjs` for the keyring; smoke script extended to 62
  checks (Node + Bun).
- **Docs**: headers reference, security model, threat model,
  configuration contract, migration runbooks, testing guide, FAQ,
  contributing bar; password/cors/security docs updated for the
  keyring and audit findings.

### Changed

- CORS documented: first `Origin` header wins (multi-header requests),
  first entry of array values wins, CORS is not authentication.
- `repository` / `bugs` / `homepage` metadata, expanded description and
  keywords in `package.json`.

### Security

- Verification paths now fail safely (return `false`) for unknown pepper
  ids, corrupt markers, over-cap costs and malformed hashes — a hostile
  database row can never crash login or force unbounded work.
- Header injection (CRLF/control characters) rejected at configuration
  time — impossible by construction at request time.
- HSTS never emitted over plain HTTP by default; `preload` guarded by
  its real preconditions.

## [1.1.0] - 2026-08-13

### Added

- **CORS module** (`Cors()` factory, exported from the package root):
  - Origin rules: wildcard, exact strings, globs
    (`https://*.example.com`), `RegExp`, dynamic callbacks and the
    literal `"null"` origin (opt-in via `allowNullOrigin`).
  - Per-origin credentials via `{ pattern, credentials }` rules;
    credentials-safe `*` reflection.
  - Preflight handling with `"auto" | "always" | "never"` modes,
    method/header subset validation, `optionsSuccessStatus`,
    `Access-Control-Max-Age`, and requested-header reflection.
  - Private Network Access support (`allowPrivateNetwork`).
  - Two deny policies: omit headers (browser enforces) or hard-block
    via `failureStatus`; `onBlock` / `onPreflight` hooks.
  - `Vary` merging — framework tokens preserved, no duplicates.
  - Four consumption surfaces: pure `process`/`processAsync`,
    Connect/Express middleware, raw `node:http` handler, and a
    Web-standard `fetchHandler` (Bun, Node ≥ 18, edge).
  - `preset: "express"` for npm-`cors` compatibility in one line.
  - Deterministic output: sorted headers, canonical method order,
    fixed emission order.
  - Construction-time validation (`CorsOptionsError`); config from
    object, JSON string, or JSON file (`{"cors": …}` unwrapped).
- **Documentation**: `docs/cors.md` reference, hub + README module
  tables updated, `examples/cors-server.mjs` and
  `examples/cors-fetch.mjs`.
- **Tooling**: CORS suite (92 tests, 178 total), smoke checks extended.

## [1.0.0] - 2026-08-13

### Added

- **Password module** (`Password()` factory) with Argon2id, bcrypt and
  scrypt drivers:
  - Full per-algorithm option surfaces (memory/time cost, parallelism,
    key/salt length, version, rounds, `preHash`, `maxmem`, …).
  - Construction-time option validation (`PasswordOptionsError`).
- **Policy engine** (`validatePassword`, `PasswordPolicyError`):
  - Length (code-point aware), character-class minimums, `minEntropy`,
    Unicode script whitelist, whitespace blocking, exact-match
    case-insensitive blocklist.
  - User-defined `customRules` (`rule`, `message`, `test`).
  - Optional `enforceOnHash` gating on `hashPassword` /
    `pepperedHashPassword`.
- **Peppering**: HMAC-SHA256 site secret with self-describing
  `$pepper$<id>$…` marker; automatic pepper application in
  `verifyPassword`; rotation-ready pepper ids; `pepperedVerifyPassword`
  supports legacy unmarked hashes.
- **Login-time rehashing**: `verifyAndRehash` (`{ valid, newHash? }`),
  `needsRehash`, `rehashPassword` (policy-free).
- **Utilities**: `detectHashAlgorithm` (pepper-aware), `isPepperedHash`,
  `stripPepperMarker`, `estimateEntropy`, `DEFAULT_PASSWORD_CONFIG`.
- **Normalization**: `normalize: "nfkc"` applied before validation and
  hashing.
- Config input via object, inline JSON string, or JSON file path (deep
  merge over defaults).
- **Documentation**: getting-started guide, full API reference,
  algorithm/policy/peppering/login/migration guides, security
  guidelines, and runnable examples.
- **Tooling**: `bun test` suite (86 tests), `tsc --noEmit`-clean,
  tsup ESM+CJS+dts build, Node and Bun smoke suites.

### Fixed

- `argon2`/`bcrypt`/`typescript`/`tsup`/`@types/bcrypt` declared and
  installed as dependencies.
- Argon2 `timeCost` default drift (config default 3 now authoritative).
- Removed a leftover scratch file that broke `tsc`.
- Tests previously targeted `vitest` while importing `bun:test`; the
  suite now runs via `bun test`.

### Security

- Verification paths never throw on malformed hashes (return `false`).
- scrypt comparison uses `timingSafeEqual`.
- Fail-fast configuration prevents out-of-range parameters at startup.
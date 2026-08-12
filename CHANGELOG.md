# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

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
# Threat model

An attacker-by-attacker view of what Maahes protects against, what it
doesn't, and the controls that matter. Keep the *residual risk* column
in mind when configuring.

## Credential attacks (Password)

| Attacker capability | Threat | Maahes control | Residual risk |
| --- | --- | --- | --- |
| DB read → offline cracking | crack password hashes | memory-hard KDF (argon2id default), unique per-hash salt, pepper (HMAC secret not stored with hashes) | weak-but-long passwords still fall to dictionary attacks — enforce `minEntropy`/blocklists |
| DB read → reuse across sites | pepper weakens hash pre-computation per site | site secret in keyring | pepper is only as good as the secret manager holding it |
| Timing analysis | user/password enumeration | uniform 401 flows, dummy-hash verification documented, constant-time compares | app-level: variable response bodies for "user exists" |
| DoS via stored hashes | hostile rows force huge KDF work on login | verify-time caps (argon2 ≤ 2²⁰ KiB/32 iters, scrypt ≤ 2¹⁸, bcrypt ≤ 31 rounds); over-cap → `false` | concurrent legitimate logins still cost CPU — rate-limit the login route |
| Confusables / Unicode | lookalike passwords, normalization bypass | NFKC normalization + `allowedScripts` | `allowedScripts` counts letters per script; digits/symbols are script-agnostic by design |
| Pepper leakage | full DB + config leak exposes the pepper | pepper never stored beside hashes, never logged | secret rotation runbook: [migration.md](migration.md#pepper-rotation) |

## Web platform attacks (SecurityHeaders + Cors)

| Threat | Header / control | Residual risk |
| --- | --- | --- |
| Clickjacking | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` | a browser that ignores both; CSP `frame-ancestors` is the modern control |
| MIME sniffing → XSS via uploaded content | `X-Content-Type-Options: nosniff` | content itself must still be served with correct types |
| Referrer leakage | `Referrer-Policy: strict-origin-when-cross-origin` | third-party resources can still see the origin |
| Cross-origin read (Spectre-class) | COOP `same-origin` + COEP `credentialless` + CORP `same-origin` (strict) | requires the full trio; breaks embedding third-party resources |
| HSTS bypass / downgrade | `Strict-Transport-Security` (secure contexts only) | first-request-in-clear still possible until preloaded; `preload` needs the real preconditions |
| Browser policy creep | `Permissions-Policy` deny-by-default for camera/mic/geo | only constrains browsers that honor it |
| Credentialed cross-origin reads | CORS engine: literal origin reflection when credentials on, `Vary` merging, first-Origin-wins | CORS is not authn/authz — server-side checks required |
| Response splitting | header-name/control-char rejection at construction | — (impossible by construction) |
| Server fingerprinting | `remove: ["Server", "X-Powered-By"]` | obfuscation, not security — patch, don't hide |
| Stored/reflected XSS payload execution | CSP: `default-src 'self'`, strict-dynamic with nonces, `object-src 'none'` | requires output encoding + a real policy; report-only policies observe first |

## DoS

| Threat | Control | Residual risk |
| --- | --- | --- |
| KDF-cost bombs in stored hashes | verify-time caps, fail-closed | — |
| Preflight flood | CORS is stateless and cheap; `maxAge` caching | app-level rate limiting |
| Header-injection payload floods | construction-time rejection, `remove`/`extra` closed sets | — |

## Supply chain & operations

| Threat | Control |
| --- | --- |
| Compromised dependency | dependabot + `npm audit` in CI, provenance on release, `dependencies` kept at exactly three runtime libs |
| Seeded secrets | pepper/env config never committed; `SECURITY.md` policy |
| Drifting security config | deterministic output + adversarial test suites per module |

## Explicit non-goals

- Stopping authenticated-account abuse, business-logic fraud, or
  application-level injection (SQL/command) in *your* query code.
- Protecting data at rest beyond password hashes (encryption module is
  planned, not shipped).
- Defense against a hostile *runtime* (compromised `node_modules`,
  malicious V8) — out of scope for a library.

## See also

- [security-model.md](security-model.md) — guarantees & principles
- [security.md](security.md) — operational checklist
- [testing.md](testing.md) — how the adversarial suites map to this table
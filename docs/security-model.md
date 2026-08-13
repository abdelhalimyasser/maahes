# Security model

How Maahes modules make security decisions, and the guarantees they make
(and don't make). Read this before tuning configuration.

## Core principles

1. **Deterministic output.** Every module is a pure function of its
   configuration and request context. Identical inputs → byte-identical
   output. No randomness inside the engine, no ambient state, no global
   mutable config. This makes security behavior testable, diffable and
   cacheable.
2. **Fail-safe defaults for decision paths, strict defaults for
   validation.** Verification of unknown/corrupt inputs returns `false`
   (never throws, never guesses); configuration that would weaken
   protection (HSTS `preload` without preconditions, a pepper marker
   with an unknown id, a wildcard paired with credentials) is rejected
   or fails closed.
3. **Fail fast on configuration.** Option errors throw at construction
   (`MaahesOptionsError` subclasses) — at boot, in tests, never in a
   request handler.
4. **No data-plane writes.** The engine never touches your database,
   your sessions, or your response bodies. It computes headers and
   verification results; you own persistence.
5. **Runtime adapters are thin and honest.** Middleware and fetch
   wrappers derive the secure context from *evidence* (TLS socket,
   `req.secure`, `https://` URL) — never from spoofable headers like
   `X-Forwarded-Proto` — and they never swallow downstream errors.
6. **Attack surface lives in the constructor, not the hot path.**
   Validation, regex compilation and pepper resolution happen once;
   request-time work is a small, closed set of pure operations.

## Module guarantees

### Password

- KDFs (Argon2id / bcrypt / scrypt) with per-hash random salts, PHC
  encoding, constant-time comparison.
- **Pepper keyring**: hashes carry a `$pepper$<id>$` marker; the ring
  selects the exact secret, so rotation never breaks old hashes and a
  new secret is used for every new hash. Unknown ids fail `false`.
- **DoS caps**: cost parameters embedded in stored hashes are bounded
  *before* any KDF work; a hostile hash can never force unbounded
  CPU/memory.
- **Migration honesty**: two migrations are deliberately non-automatable
  (bcrypt `preHash` flip, normalization change). The library reports
  `valid: false` rather than guessing.
- Password hashes never leave the module as plaintext, and errors never
  include passwords or hashes.

### Cors

- Origin matching is deterministic and case-normalized (scheme, host).
- A wildcard is never paired with `Access-Control-Allow-Credentials:
  true` (the browser would reject it anyway — the reflection is literal
  instead).
- `Vary` is merged, never clobbered; block decisions omit headers by
  default (browser enforces) with an optional hard-block status.

### SecurityHeaders

- Emission order is canonical and fixed; extras are sorted; removal is
  case-insensitive.
- HSTS only in secure contexts; `preload` guarded by its real
  preconditions.
- CRLF/splitting is impossible by construction (control characters are
  rejected at configuration time).
- CSP only when explicitly configured — never a surprise policy that
  breaks your app; the `csp` option is emitted first and validated by
  the dedicated module's strict grammar.

## What Maahes does NOT do

- **It is not a firewall.** Origin checks, header sets and password
  verification do not stop application-level abuse (broken authz, IDOR,
  injection in your query logic, business-logic fraud).
- **It cannot fix bad secrets.** Pepper/argon2 secrets belong in a
  secret manager, never in the repo; see `SECURITY.md`.
- **It cannot verify what you store.** `pepperedVerifyPassword` for
  legacy *unmarked* hashes tries the ring in order — if an attacker
  could write hashes, the ring won't save you.
- **Determinism ≠ invulnerability.** Adversaries are presumed to know
  the configuration.

## See also

- [threat-model.md](threat-model.md) — attacker-by-attacker analysis
- [configuration.md](configuration.md) — shared config conventions
- [security.md](security.md) — operational checklist
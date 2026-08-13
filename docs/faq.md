# FAQ

## General

**Why is the factory named `SecurityHeaders`, not `Headers`?**
The Web Platform already owns a global `Headers` type and constructor.
`SecurityHeaders` avoids shadowing it and makes imports unambiguous.

**What runtimes are supported?** Node ≥ 18 and Bun, ESM and CJS. The
fetch adapters use only Web-standard APIs, so edge runtimes (Cloudflare
Workers, Deno, …) work where the runtime provides `Request`/`Response`.

**Why so few runtime dependencies?** Exactly three:
`@node-rs/argon2`, `bcryptjs`, `node:crypto` (scrypt). Fewer
dependencies = smaller attack surface; dependabot + `npm audit` in CI
keep them watched.

**Does Maahes have a CSP module?** Not yet — and deliberately,
`SecurityHeaders` never emits `Content-Security-Policy` (the emission
slot is reserved). A `csp` module is on the roadmap so policies get the
same deterministic, tested treatment as the rest.

## Password

**Why did the default `allowedScripts` change to `["Any"]`?**
The old `["Latin"]` default silently rejected legitimate non-Latin
passwords (Arabic, Cyrillic, …) on signup — a real-world correctness
bug. Restricting scripts remains available as an explicit policy
choice; it is no longer the default surprise.

**`verifyPassword` returns `false` for a hash I generated myself — why?**
Check the pepper: marked hashes route to the secret whose id is in the
marker; if your ring doesn't contain that id, verification fails
safely. Also confirm the algorithm's driver options match the stored
hash's parameters (parameter drift is *detected*, but bcrypt `preHash`
and normalization changes are non-automatable — see
[migration.md](migration.md#3-bcrypt-prehash-flip--not-automatable)).

**How can verification fail on a *malformed* hash without crashing?**
Verification is total: unknown formats, corrupt PHC, over-cap cost
parameters and unknown pepper ids all return `false`
(`needsRehash: true` where applicable). A hostile database row can
never crash the login path.

**Pepper doesn't help against a full leak — why bother?** It protects
against *partial* leaks: hashes without the secret (e.g. an
unencrypted SQL dump) can't be pre-computed against a known pepper, and
the same stolen hash set is useless on another site. Keyring rotation
keeps the secret fresh when it does leak.

**Should I store the pepper with the hashes?** No — that equals no
pepper. Secret manager, environment, or KMS; never the same backup.

## CORS

**`origin: "*"` with `credentials: true` — what happens?** The matching
origin is reflected literally instead of `*` (a wildcard with
credentials is rejected by browsers anyway), and `Vary: Origin` is
added. This is the safe, correct reflection — never a leak of `*`.

**Multiple `Origin` headers arrived — what did the engine do?** The
first entry wins (mirroring Node's header representation); the rest are
ignored. Array values in `headers` behave the same (first entry wins,
Fetch-spec serialization style).

**Is CORS authentication?** No. It gates what *browsers* may read
cross-origin. Server-to-server and non-browser clients ignore it —
enforce authn/authz server-side regardless.

## SecurityHeaders

**Why is HSTS absent over plain HTTP?** `httpsOnly` (default `true`)
suppresses the header when the context isn't secure: browsers ignore
HSTS on HTTP anyway, and emitting it from a downgrade-capable proxy
would be wrong. Set `httpsOnly: false` only with a TLS-terminating
edge.

**`preload: true` throws at construction — why?** The HSTS preload list
requires `maxAge ≥ 31536000` and `includeSubDomains`. Failing at boot
means a broken preload intent can't ship silently.

**`overwrite: false` — what exactly wins?** Headers already present on
the response *before* the middleware runs (or on the handler's
`Response` for the fetch wrapper) keep their values; Maahes only fills
in what's missing. `remove` still strips listed names.

**Why is `X-XSS-Protection: "0"` the default?** The legacy XSS filter
is disabled-by-default in modern browsers and its "block" mode caused
real-world bypasses. `"0"` documents the decision instead of implying
protection. The real XSS defense is CSP (planned module) + output
encoding.

**How do I add a custom header?** `extra: { "X-Request-Id": "…" }` —
validated, sorted, appended after the known set. Engine-owned header
names are rejected there (they're configured via their own options).

## Roadmap

**What's planned?** CSP, CSRF protection, hashing (generic), encryption,
rate limiting, secrets management, XSS helpers, SQL-injection guards,
audit logging. Each module ships with the same contracts: deterministic
engine, fail-fast config, adversarial tests, examples, docs.

## See also

- [configuration.md](configuration.md) — shared config contract
- [threat-model.md](threat-model.md) — what the toolkit does and doesn't stop
- [security.md](security.md) — hardening checklist
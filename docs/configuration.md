# Configuration

Shared conventions across every Maahes module (`Password`, `Cors`,
`SecurityHeaders`).

## The config contract

All three factories accept the same three input forms:

```ts
// 1. Plain object
Password({ algorithm: "argon2", policy: { minLength: 10 } });

// 2. Inline JSON string (Ops tooling, env-var delivery)
SecurityHeaders('{"preset":"strict","remove":["Server"]}');

// 3. JSON file path — an optional module-named wrapper is unwrapped
Cors("./cors.json");
// cors.json: { "cors": { "origin": ["https://app.example.com"] } }
```

Resolution order is always **defaults → preset → user**, deep merged at
every level (nested objects like `argon2`/`policy`/`hsts` merge
recursively; arrays replace). Explicit user options always beat presets;
presets always beat defaults.

## Validation

- All option errors throw at **construction** time as
  `MaahesOptionsError` subclasses (`PasswordOptionsError`,
  `CorsOptionsError`, `SecurityHeadersOptionsError`). One `try/catch`
  around app bootstrap, never error handling in request handlers.
- Every module error extends the shared base, so
  `err instanceof MaahesError` catches the whole toolkit:

```ts
import { MaahesError } from "@maahes/core";

try {
  Password({ scrypt: { cost: 1000 } });
} catch (err) {
  if (err instanceof MaahesError) log(err.message); // "scrypt.cost must be a power of two >= 2"
}
```

- Validation happens even for options that are not "active" (all driver
  option sets, all header options) — a later config change can't
  silently ship an invalid value.

## Purity & determinism

- Factories are pure: configuration objects are never mutated. Frozen
  configs (`Object.freeze`) are legal inputs.
- Instances are immutable and share-safe across requests/workers: they
  hold resolved config and compiled matchers only.
- Outputs are deterministic: identical config + context → identical
  result, in identical order. Use it for tests, caching and canary
  diffs.

## Environment & secrets

- `PASSWORD_PEPPER` is honored as a fallback for `Password({ pepper })`.
  Prefer an explicit keyring, and load secrets from a secret manager —
  never from the repository.
- Never log passwords, hashes or pepper material. Errors carry option
  names and ranges, not values.

## Per-module references

| Module | Config doc | Defaults source |
| --- | --- | --- |
| `Password` | [password.md](password.md#4-algorithms--configuration) | `DEFAULT_PASSWORD_CONFIG` |
| `Cors` | [cors.md](cors.md#configuration) | `DEFAULT_CORS_CONFIG` |
| `SecurityHeaders` | [headers.md](headers.md#3-api-reference) | `DEFAULT_HEADERS_CONFIG` |

## Recommended baseline

```ts
Password({
  algorithm: "argon2",
  argon2: { memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 },
  pepper: { current: { id: "2026-a", secret: process.env.PASSWORD_PEPPER } },
  normalize: "nfkc",
  policy: { minLength: 10, minDigits: 1, minSymbols: 1, minEntropy: 50, enforceOnHash: true },
});

Cors({
  origin: ["https://app.example.com", "https://*.example.com"],
  credentials: false, // per-origin rules may re-enable
  maxAge: 3600,
});

SecurityHeaders({ preset: "default", remove: ["Server", "X-Powered-By"] });
```

See [security.md](security.md) for rationale and the yearly review
checklist.
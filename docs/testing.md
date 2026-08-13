# Testing

How Maahes tests itself, and how to test your own Maahes configuration.

## Suite layout

```
test/
  password/   config · drivers · policy · detect · factory · migration · adversarial
  cors/       config · core · adapters · adversarial
  headers/    config · core · adapters · adversarial
```

Every module gets:

- **behavioral** suites (configuration resolution, engine output,
  adapters),
- an **adversarial** suite: hostile inputs, boundary abuse, purity under
  frozen objects, ordering stability, fail-closed paths.

## Running

```bash
bun install
bun test            # whole suite (3 modules)
bun test test/password
bun test test/headers --bail   # stop at first failure
npm run typecheck   # tsc --noEmit (must stay clean)
npm run build       # dist/ via tsup (ESM + CJS + d.ts)
npm run smoke:node  # dist/ exercised under Node
npm run smoke:bun   # dist/ exercised under Bun
```

## Adversarial suites — what they pin down

| Suite | Pins down |
| --- | --- |
| `password/adversarial` | malformed/corrupt hashes, forged & unknown pepper ids, rotation lifecycle, caps over limit → `false`, legacy unmarked hashes, Unicode/null-byte/whitespace inputs, migration matrices, secret-leak assertions (errors never contain passwords/peppers) |
| `cors/adversarial` | hostile origins (multi-`Origin` headers, array entries), credential/wildcard pairing, `Vary` merging, denial surfaces |
| `headers/adversarial` | CRLF/splitting on every configurable value, hostile names, HSTS misuse, cross-origin-isolation constraints, engine-owned-header spoofing, frozen-input purity, ordering stability |

## Testing your own configuration

Because output is deterministic, config tests are cheap and meaningful:

```ts
import { Password, SecurityHeaders, Cors } from "@maahes/core";

// Headers: golden snapshot
const plan = SecurityHeaders({ preset: "strict" }).build({ secure: true });
expect(plan.headers).toEqual({
  "Cross-Origin-Embedder-Policy": "credentialless",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
});

// Password: the login contract that must never regress
const { valid, newHash } = await pwd.verifyAndRehash(storedHash, password);
expect(valid).toBe(true);
expect(newHash === undefined || newHash !== storedHash).toBe(true);

// CORS: deny is deny
expect(cors.process({ method: "GET", headers: { origin: "https://evil.io" } }).allowed).toBe(false);
```

Golden values come from `DEFAULT_*_CONFIG` + presets — prefer snapshot
tests over recomputing defaults by hand.

## Contribution

See [contributing.md](contributing.md) for the checklist every new
module/test must satisfy before merging (including an adversarial suite
for the new module).
# `Csp` module

> Module home: `src/csp/` · Type reference: `src/csp/types.ts`
> (all types are re-exported from the package root).

## 1. Overview

A deterministic Content Security Policy engine. Configure directives
once, build a policy per request (nonce-aware), audit existing policies
with a strict parser — or plug a static policy straight into the
`SecurityHeaders` module, which emits it first in its canonical header
order (position 1 was reserved for CSP from day one).

**Feature highlights**

- **Presets** — `minimal` / `default` / `strict` (the modern
  strict-dynamic pattern), each overridable directive-by-directive.
- **Determinism** — directives sorted by name, sources in their
  configured order (order matters in CSP 3 precedence); identical config
  + context → identical policy.
- **Injection-safe grammar** — directive names are RFC 7230 tokens;
  source values reject control characters, `;`, `,` and `"` at
  construction — directive or policy injection is impossible.
- **Nonce support** — `'nonce-$nonce'` templates are filled from the
  build context; building without a nonce fails loud
  (`CspOptionsError`) instead of emitting a broken policy.
- **Report-only** — `reportOnly: true` emits
  `Content-Security-Policy-Report-Only` for observing violations before
  enforcing.
- **Strict parser** — `parse()`/`parseCsp` read existing policies and
  reject duplicates, `'none'` misuse and hostile input.
- **Headers integration** — `SecurityHeaders({ csp })` accepts a config
  or serialized policy and emits it first (no per-request nonce in that
  channel — use the `Csp` module for nonce-based policies).

## 2. Quick start

```ts
import { Csp, SecurityHeaders } from "@maahes/core";

// Static policy wired into SecurityHeaders — one line, emitted first.
app.use(SecurityHeaders({ csp: "default-src 'self'" }).middleware());

// Nonce-based strict policy, per request (Google's strict-dynamic pattern):
const csp = Csp({ preset: "strict" });

app.get("/", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("base64url");
  const { headers } = csp.build({ nonce });
  res.setHeader("Content-Security-Policy", headers["Content-Security-Policy"]);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.send(renderPage(nonce)); // nonce on your <script> tags
});
```

`Csp()` with no arguments yields the safe baseline below. The strict
preset cannot be built without a nonce — by design.

## 3. API reference

### `Csp(input?) → CspModule`

| Member | Signature | Notes |
| --- | --- | --- |
| `build` | `(context?: CspBuildContext) => CspPlan` | Pure & synchronous. `CspPlan = { headers }` — one header (`Content-Security-Policy` or `-Report-Only`) |
| `headers` | `(context?) => Headers` | Web-standard `Headers` view |
| `policy` | `(context?) => string` | Serialized policy (directives sorted, sources in order) |
| `parse` | `(policy: string) => CspParsed` | Strict parse → `{ directives }` |

### Input forms

```ts
Csp();                                          // "default" preset
Csp({ preset: "strict" });                      // config object
Csp('{"directives":{"script-src":["'self'"]}}'); // inline JSON
Csp("./csp.json");                              // file ({"csp": …} unwrapped)
Csp("default-src 'self'; frame-ancestors 'none'"); // RAW policy — replaces defaults entirely
```

### Standalone exports

| Export | Description |
| --- | --- |
| `DEFAULT_CSP_CONFIG` | canonical baseline (introspection / tooling) |
| `CSP_PRESETS` | `{ minimal, default, strict }` directive maps |
| `parseCsp` / `serializeCsp` / `buildCsp` | strict parser / canonical serializer / pure engine |
| `parseCspConfigInput` / `resolveCspConfig` | input normalization / resolution + validation |
| `CspOptionsError` | construction & nonce errors (extends `MaahesOptionsError`) |

### Types

```ts
interface CspConfig {
  preset?: "minimal" | "default" | "strict";
  directives?: Record<string, string[] | string>; // per-name merge over the preset
  reportOnly?: boolean;                            // default false
}

interface CspBuildContext {
  nonce?: string;   // required by 'nonce-$nonce' templates; [A-Za-z0-9+/=_-]+
}
```

## 4. Presets

| Directive | minimal | default | strict |
| --- | --- | --- | --- |
| `base-uri` | `'self'` | `'self'` | `'self'` |
| `default-src` | — | `'self'` | `'self'` |
| `frame-ancestors` | `'none'` | `'none'` | `'none'` |
| `object-src` | `'none'` | `'none'` | `'none'` |
| `script-src` | — | — | `'nonce-$nonce' 'strict-dynamic'` |

- `minimal`: hardening that never constrains how scripts/styles load —
  clickjacking (`frame-ancestors`), plugin content (`object-src`),
  base-URI hijacking (`base-uri`).
- `default`: minimal + `default-src 'self'` — requires first-party
  assets only; relax `default-src` (or add `script-src`/`style-src`) for
  CDN-loaded content.
- `strict`: the modern strict-dynamic pattern — nonce-based scripts.
  **Requires a nonce at build time** (fail loud).

Presets **replace** the baseline directive map wholesale (that's what
makes `minimal` actually minimal); user `directives` then merge per
directive name over the preset.

## 5. Nonces

```ts
const csp = Csp({
  directives: { "script-src": ["'nonce-$nonce'", "'strict-dynamic'"] },
});

csp.policy({ nonce: "abc123" });
// "script-src 'nonce-abc123' 'strict-dynamic'" (plus preset directives)

csp.policy(); // throws CspOptionsError — never emits a broken policy
```

Nonce values are validated (`[A-Za-z0-9+/=_-]+`) and the template is the
only legal `$nonce` usage. Nonce policies remain deterministic for equal
contexts — safe to snapshot and test.

## 6. Report-only

```ts
const report = Csp({ preset: "default", reportOnly: true });
report.headers().get("Content-Security-Policy-Report-Only");
// "base-uri 'self'; default-src 'self'; ..."
```

Ship the enforcing policy alongside a report-only one to observe
violations before tightening (browsers send reports to the `report-to`/
`report-uri` directive you configure).

## 7. SecurityHeaders integration

```ts
SecurityHeaders({ csp: "default-src 'self'" });            // serialized policy
SecurityHeaders({ csp: { directives: { "default-src": ["'self'"] } } }); // config
SecurityHeaders();                                          // no CSP — never a surprise policy
```

- Emitted **first** in the canonical header order (position 1 of
  `KNOWN_HEADER_ORDER`, reserved since the headers module shipped).
- Participates in `overwrite` semantics; `csp: false` disables; extras
  cannot spoof it.
- `'nonce-$nonce'` templates are rejected in this channel (no per-request
  nonce) — use the standalone `Csp` module for nonce policies.
- Policy errors surface as `SecurityHeadersOptionsError` at construction.

## 8. Run it

```bash
node examples/csp-server.mjs   # static + nonce-based policies on node:http
# works identically with `bun`; curl -i localhost:3002 to inspect
```

## 9. See also

- [headers.md](headers.md) — the header engine CSP plugs into
- [threat-model.md](threat-model.md) — what CSP does and does not stop
- [security.md](security.md) — hardening checklist
# `SecurityHeaders` module

> Module home: `src/headers/` · Type reference: `src/headers/types.ts`
> (all types are re-exported from the package root).

## 1. Overview

A deterministic, framework-agnostic security headers engine. Configure
once, then consume through a pure builder, a Connect/Express middleware
or a Web-standard fetch wrapper (Node ≥ 18, Bun, edge runtimes).

The factory is named `SecurityHeaders` — **not** `Headers` — because the
Web Platform already owns a global `Headers` type and constructor.

**Feature highlights**

- **Presets** — `minimal` / `default` / `strict`, each overridable
  option-by-option (deep merge).
- **Determinism** — fixed emission order (`KNOWN_HEADER_ORDER`), extras
  sorted with `localeCompare`; identical config + context → byte-identical
  output. Safe to diff, cache and test.
- **No surprises** — `Content-Security-Policy` is **never** emitted by
  this module (a dedicated `csp` module is planned; the slot is reserved).
- **Secure by default** — HSTS is only served in secure contexts
  (`httpsOnly: true` default); `preload` demands the preconditions the
  preload list requires (fail fast, at construction).
- **Fail-fast validation** — header names must be RFC 7230 tokens,
  values must not contain control characters (CRLF/splitting is
  rejected at construction, never at request time).
- **Respectful** — `overwrite: false` lets your framework's existing
  headers win; `remove` strips fingerprinting headers
  (`Server`, `X-Powered-By`, …) case-insensitively.
- **Never breaks requests** — the middleware always calls `next()`,
  never ends requests, and never swallows downstream errors.

## 2. Quick start

```ts
import { SecurityHeaders } from "@maahes/core";

// Express / Connect / Koa-style
const headers = SecurityHeaders({ preset: "strict", remove: ["Server"] });
app.use(headers.middleware());

// Web-standard (Bun.serve, Node 18+, edge)
server.fetch = headers.fetchHandler(route);

// Pure, synchronous plan (tests, caching, serverless functions)
const { headers: out } = headers.build({ secure: true });
// { "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", ... }
```

## 3. API reference

### `SecurityHeaders(input?) → SecurityHeadersModule`

| Member | Signature | Notes |
| --- | --- | --- |
| `build` | `(context?) => HeaderPlan` | Pure & synchronous. `HeaderPlan = { headers, removed }` |
| `headers` | `(context?) => Headers` | Web-standard `Headers` view of the same plan |
| `middleware` | `() => (req, res, next?) => void` | Connect/Express; always calls `next()` |
| `fetchHandler` | `(handler?) => (req: Request) => Promise<Response>` | Wraps your handler, preserves status/statusText/body |

### `HeaderBuildContext`

```ts
interface HeaderBuildContext {
  secure?: boolean;   // default true for build(); middleware/fetch derive it
  existing?: Headers | Record<string, string> | [string, string][];
}
```

`build()` assumes `secure: true` when omitted (safe default for
TLS-terminating hosts). The middleware derives it from
`req.secure ?? req.socket.encrypted` — Express's `trust proxy`
configuration and the raw TLS socket — and the fetch wrapper from
`request.url.startsWith("https://")`. **`X-Forwarded-Proto` is never
trusted directly.**

### Standalone exports

| Export | Description |
| --- | --- |
| `DEFAULT_HEADERS_CONFIG` | canonical defaults (introspection / tooling) |
| `PRESETS` | `{ minimal, default, strict }` config fragments |
| `buildHeaderSet` / `KNOWN_HEADER_ORDER` / `normalizeExisting` | pure engine + canonical order (for advanced users) |
| `parseHeadersConfigInput` | object / JSON string / JSON file (`{"headers": …}` unwrapped) |
| `resolveHeadersConfig` | defaults → preset → user, deep merged and validated |
| `SecurityHeadersOptionsError` | construction-time option errors (extends `MaahesOptionsError`) |

### Types

```ts
interface SecurityHeadersConfig {
  preset?: "minimal" | "default" | "strict";
  httpsOnly?: boolean;            // default true — HSTS only on secure contexts
  overwrite?: boolean;            // default true — replace same-named existing headers
  remove?: string[];              // fingerprinting headers to strip
  extra?: Record<string, string>; // sorted, appended after known headers
  hsts?: HstsConfig | false;      // default { maxAge: 31536000, includeSubDomains: true, preload: false }
  frameOptions?: FrameOptionsValue | false;   // default "DENY"
  referrerPolicy?: ReferrerPolicyValue | false; // default "strict-origin-when-cross-origin"
  nosniff?: boolean;              // default true
  coop?: CoopValue | false;       // default "same-origin"
  coep?: CoepValue | false;       // default "credentialless"
  corp?: CorpValue | false;       // default false (strict preset: "same-origin")
  permissionsPolicy?: string | false; // default "camera=(), microphone=(), geolocation=()"
  xssProtection?: XssProtectionValue | false; // default "0" (never "1; mode=block" alone)
  crossDomainPolicy?: CrossDomainPolicyValue | false; // default "none"
  dnsPrefetchControl?: boolean;   // default false — opt-in "X-DNS-Prefetch-Control: off"
  originAgentCluster?: boolean;   // default false — opt-in "Origin-Agent-Cluster: ?1"
}
```

## 4. Presets

| Option | minimal | default | strict |
| --- | --- | --- | --- |
| `nosniff` | ✅ | ✅ | ✅ |
| `frameOptions` | `DENY` | `DENY` | `DENY` |
| `referrerPolicy` | `strict-origin-when-cross-origin` | `strict-origin-when-cross-origin` | `no-referrer` |
| `coop` / `coep` | — | `same-origin` / `credentialless` | `same-origin` / `credentialless` |
| `corp` | — | — | `same-origin` |
| `permissionsPolicy` | — | `camera=(), microphone=(), geolocation=()` | same |
| `xssProtection` | — | `0` | `0` |
| `crossDomainPolicy` | — | `none` | `none` |

Explicit options always beat the preset. The default preset is a
reasoned baseline; `strict` additionally locks referrers down and closes
cross-origin resource sharing (CORP) — use it when your app does not
need to load cross-origin subresources.

## 5. HSTS

```ts
const headers = SecurityHeaders({
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
});
```

- `maxAge` is validated to `[0, 631138519]` (RFC 6797 §6.1).
- `preload: true` requires `maxAge >= 31536000` and
  `includeSubDomains: true` — anything else throws
  `SecurityHeadersOptionsError` at construction, so a broken preload
  config can never reach production.
- `httpsOnly` (default `true`): over plain HTTP the HSTS header is
  suppressed — a header the browser would ignore on HTTP anyway, and one
  that must never leak from a downgrade-capable proxy. Set
  `httpsOnly: false` only if you serve HSTS from an HTTP edge.

## 6. Adapters

### Middleware

```ts
import { createServer } from "node:http";
const headers = SecurityHeaders({ remove: ["Server"] });

createServer((req, res) => {
  headers.middleware()(req, res, () => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
});
```

Contract: decorates the response, **always** calls `next()`, never ends
the request, and errors propagate to `next(err)` (or rethrow when `next`
is omitted). Existing headers are read at middleware time, so
`overwrite: false` reflects whatever the app set before the middleware
ran.

### Fetch wrapper

```ts
server.fetch = headers.fetchHandler(async (request) => {
  return new Response("ok", { status: 200 });
});
```

Wraps any handler; the returned `Response` preserves status, statusText
and body, `Set-Cookie` survives untouched, and downstream errors always
propagate.

## 7. Configuration input

Same contract as `Password`/`Cors` — object, inline JSON string, or JSON
file path with an optional `{"headers": …}` wrapper:

```ts
const headers = SecurityHeaders("./headers.json");
// headers.json: { "headers": { "preset": "strict", "remove": ["Server"] } }
```

## 8. Run it

```bash
node examples/headers-server.mjs   # middleware on raw node:http
node examples/headers-fetch.mjs    # fetch wrapper bridged into HTTP
# works identically with `bun`; curl -i localhost:3000 to inspect
```

## 9. See also

- [security-model.md](security-model.md) — header-by-header rationale
- [threat-model.md](threat-model.md) — what these headers do and do not stop
- [getting-started.md](getting-started.md) — runtimes, install, conventions
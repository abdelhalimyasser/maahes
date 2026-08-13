# CORS module

The Maahes CORS module is a framework-agnostic cross-origin resource
sharing engine. Configure it once, then consume it through the surface
that fits your stack — a pure processor, a Connect/Express middleware,
a raw `node:http` handler or a Web-standard fetch wrapper (Bun, Node ≥
18, edge runtimes).

It ships the classic features plus extras you usually have to assemble
yourself:

- origin rules: exact strings, globs (`https://*.example.com`),
  RegExp, arrays, dynamic callbacks, the wildcard, the literal `null`
  origin
- per-origin credentials — one module serving a public API and a
  credentialed admin app
- credentials-safe `*` reflection (never leaks a wildcard alongside
  `Access-Control-Allow-Credentials: true`)
- preflight validation of methods and headers (subset checks), with
  `"auto" | "always" | "never"` detection modes
- Private Network Access support (`Access-Control-Request-Private-Network`)
- `Vary` **merging** — a framework's existing `Vary` is never clobbered
- two deny policies: omit headers (browser blocks) or hard-block with a
  status code, plus `onBlock` / `onPreflight` hooks
- deterministic output: sorted headers, canonical method order, fixed
  emission order — safe to diff, cache and test

## Security notes

**CORS is not authentication.** The engine answers the browser's CORS
protocol; it does not decide *who* may call your API. A reflected origin
grants the *browser* permission to read the response — any non-browser
client (curl, server-to-server, bots) can send whatever `Origin` it
likes. Always enforce real authentication and authorization
(`Authorization` headers, sessions, server-side origin allowlists) on
the routes themselves.

- **Multiple `Origin` headers** (a malformed or hostile request can carry
  several): the first one wins, mirroring how Node's `req.headers`
  presents duplicates. The engine never echoes more than one origin.
- **Array values** in `headers` (e.g. `origin: ["https://a", "https://b"]`):
  the first entry is used for the decision and reflection — same rule as
  the Fetch spec's single-value serialization. The remaining entries are
  ignored.
- **Never pair a wildcard with credentials**: with `credentials: true`,
  a matching origin is reflected literally instead of `*`, so the browser
  will not reject the credentialed response.
- **`Vary` discipline**: responses whose CORS headers depend on the
  request's `Origin` must advertise it. The engine merges `Vary`
  automatically (see Guide 2) — never strip that header downstream.

## Quick start

```ts
import { Cors } from "@maahes/core";

const cors = Cors({
  origin: [
    "https://app.example.com",          // exact
    "https://*.example.com",            // glob (wildcards are never allowed to cross the scheme)
    { pattern: "https://admin.example.com", credentials: true },
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  exposedHeaders: ["x-total-count"],
});

// Express / Connect / Koa-style
app.use(cors.middleware());

// Raw node:http — no framework needed
http.createServer(cors.middleware()).listen(3000);

// Web-standard (Bun.serve, Node 18+, edge runtimes)
server.fetch = cors.fetchHandler(route);
```

`Cors()` with no arguments yields the secure defaults below. Run the
end-to-end examples to see all three surfaces in action:

- [cors-server.mjs](../examples/cors-server.mjs) — Express middleware +
  raw node server
- [cors-fetch.mjs](../examples/cors-fetch.mjs) — fetch wrapper on
  Bun/Node

## API

| Export | Signature | Notes |
| --- | --- | --- |
| `Cors` | `(input?: CorsConfig \| string) => CorsModule` | Default export of the module; also exported from the package root |
| `CorsModule.process` | `(input: CorsRequestInput) => CorsResult` | Pure, synchronous, no I/O. Throws for callback origins |
| `CorsModule.processAsync` | `(input) => Promise<CorsResult>` | Required for callback-based origins |
| `CorsModule.middleware` | `() => CorsMiddleware` | `(req, res, next?)` — `next` omitted = raw node handler |
| `CorsModule.fetchHandler` | `(handler?) => (req: Request) => Promise<Response \| undefined>` | Without `handler`: CORS-only adapter |
| `CorsModule.isPreflight` | `(input) => boolean` | Honors the configured `preflight` mode |
| `CorsModule.allowedOrigin` | `(origin) => string \| null` | `null` = denied |
| `CorsOptionsError` | `class extends Error` | Thrown at construction for invalid options |
| `DEFAULT_CORS_CONFIG` | `const` | Fully-populated defaults, single source of truth |
| `parseCorsConfigInput` | `(input) => CorsConfig` | Object / JSON string / JSON file (`{"cors": …}` unwrapped) |
| `resolveConfig` | `(user) => CorsConfig` | Defaults → preset → user, deep merged and validated |
| engine + matcher helpers | see [src/cors](`../src/cors`) | `createEngine`, `compileOrigin`, `compileGlob`, `mergeVary`, … |

### CorsRequestInput

```ts
interface CorsRequestInput {
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
  origin?: string; // bypasses the Origin header (programmatic)
}
```

### CorsResult

```ts
interface CorsResult {
  allowed: boolean;          // proceed?
  blocked: boolean;          // explicit origin was denied
  preflight: boolean;
  statusCode?: number;       // preflight success / hard-block status
  headers: Record<string, string>; // set every entry on the response
  origin: string | null;
}
```

## Configuration

Every option is optional; unset fields fall back to the defaults (deep
merge, same contract as the Password module).

| Option | Default | Description |
| --- | --- | --- |
| `origin` | `"*"` | `"*"`, string, `string[]`, `RegExp`, rule array, callback |
| `allowlist` | — | Alias merged into `origin` (strings and/or rules) |
| `matchMode` | `"auto"` | `"exact" \| "glob" \| "regex" \| "auto"` (wildcards present → glob) |
| `methods` | `GET, HEAD, PUT, PATCH, POST, DELETE` | Allowed preflight methods (emitted sorted) |
| `allowedHeaders` | `true` (reflect) | `string[]` subset-validated, or `true` to reflect requested |
| `exposedHeaders` | `[]` | `Access-Control-Expose-Headers` (emitted sorted) |
| `credentials` | `false` | Per-origin rules can override per Origin |
| `maxAge` | `86400` | Preflight cache in seconds |
| `preflight` | `"auto"` | `"auto" \| "always" \| "never"` |
| `optionsSuccessStatus` | `204` | Status for successful preflights |
| `allowPrivateNetwork` | `false` | PNA opt-in (header answered `true`) |
| `allowNullOrigin` | `false` | Admit the literal `"null"` origin |
| `failureStatus` | — | Unset: omit headers. Set: hard-block with this status |
| `onBlock` | — | `({ origin, request }) => void` — abuse signal / logging |
| `onPreflight` | — | `({ origin, request, result }) => void` — analytics |
| `preset` | `"default"` | `"express"` = answer every OPTIONS (npm-`cors` compat) |

Invalid values throw `CorsOptionsError` at construction — one
`try/catch` at boot, never in request handlers.

### Presets

`preset: "express"` reproduces the observable behavior of the popular
npm `cors` package in one line (used to migrate without surprises):

```ts
import { Cors } from "@maahes/core";
import cors from "cors";

app.use(cors());            // ← the package you might be replacing
app.use(Cors({ preset: "express" }).middleware());
```

Explicit options always beat the preset.

### Configuration input

Pass an object, an inline JSON string, or a JSON file path — a common
Ops pattern:

```ts
import { Cors } from "@maahes/core";

const cors = Cors("./cors.json");

// cors.json
// { "cors": { "origin": ["https://app.example.com"], "credentials": true } }
```

A `{"cors": …}` wrapper is unwrapped automatically.

## Guides

### 1. Public API + credentialed admin in one module

A single module serves both: the public widget gets no credentials, the
admin panel does — even with a shared origin rule list.

```ts
const cors = Cors({
  origin: [
    "https://*.example.com",
    { pattern: "https://admin.example.com", credentials: true },
  ],
  credentials: false, // global default stays locked down
});
```

### 2. Remember the `Vary` discipline

Any response whose CORS headers depend on the request's `Origin` must
advertise it. The engine merges `Vary` automatically — your framework's
existing tokens are preserved, and no duplicates are emitted:

```ts
cors.process({
  method: "GET",
  headers: { origin: "https://app.example.com", vary: "Accept-Encoding" },
}).headers["Vary"];
// "Accept-Encoding, Origin"
```

### 3. Leave a paper trail

```ts
const cors = Cors({
  origin: ["https://app.example.com"],
  failureStatus: 403,
  onBlock: ({ origin, request }) => {
    console.error(`[cors] blocked ${origin} ${request.method} ${request.headers?.["user-agent"]}`);
  },
  onPreflight: ({ origin, result }) => {
    if (result.allowed) metrics.preflightAllowed.inc({ origin });
  },
});
```

### 4. Migrating from the npm `cors` package

1. Swap `app.use(cors(options))` for
   `app.use(Cors({ ...options, preset: "express" }).middleware())` —
   preflight detection (`"always"`) and requested-header reflection
   behave the same.
2. `origin: "*"` default stays a wildcard, but note the safer baseline:
   `credentials` is `false` by default here (npm `cors` defaults to
   `true`). Re-enable it explicitly.
3. Drop `optionsSuccessStatus` → keep it, it is supported.
4. Your `origin: (origin, cb) => …` callbacks keep working — they now
   run through `processAsync`/`fetchHandler` (and route through the
   middleware automatically where the middleware drives them).

## Examples

- [examples/cors-server.mjs](../examples/cors-server.mjs) — Express-style
  middleware and a raw `node:http` server answering same-origin and
  cross-origin calls
- [examples/cors-fetch.mjs](../examples/cors-fetch.mjs) — the
  Web-standard wrapper in a minimal Bun/Node server

Run them on Node or Bun after `npm run build`.

## See also

- [getting-started.md](getting-started.md) — runtimes, install,
  conventions
- [security.md](security.md) — hardening checklist (CORS is item 2)
- [threat-model.md](threat-model.md) — what CORS can and cannot protect
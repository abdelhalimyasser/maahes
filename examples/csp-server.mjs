#!/usr/bin/env node
/**
 * Content Security Policy on a plain Node HTTP server (no frameworks).
 *
 * Shows: static policy via SecurityHeaders, preset-based Csp module,
 * per-request nonces (strict-dynamic pattern), and report-only mode.
 * Run:  node examples/csp-server.mjs   (then curl -i localhost:3002)
 */

import { createServer } from "node:http";
import { Csp, SecurityHeaders } from "../dist/index.js";

const PORT = 3002;

const staticCsp = Csp({ preset: "default" });
const strictCsp = Csp({
  preset: "strict",
  directives: { "style-src": ["'self'"] },
});
const reportOnly = Csp({ preset: "strict", reportOnly: true });

const headers = SecurityHeaders({
  preset: "default",
  remove: ["Server", "X-Powered-By"],
  csp: "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'",
});

function nonce() {
  const b = crypto.getRandomValues(new Uint8Array(18));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const server = createServer((req, res) => {
  const n = nonce();

  const { headers: staticHeaders } = staticCsp.build();
  const { headers: strictHeaders } = strictCsp.build({ nonce: n });
  const { headers: reportHeaders } = reportOnly.build({ nonce: n });

  const { headers: engine } = headers.run(req, res);

  res.writeHead(200, {
    ...engine,
    ...staticHeaders,
    ...strictHeaders,
    ...reportHeaders,
    "Content-Type": "text/html",
  });
  res.end(`<!doctype html>
<title>CSP example</title>
<h1>Maahes CSP</h1>
<p>Static policy + strict-dynamic policy with a per-request nonce.</p>
<script nonce="${n}">document.title = "CSP example (script ran)";</script>
`);
});

server.listen(PORT, () => {
  console.log(`CSP example server on http://localhost:${PORT}`);
  console.log(`Static policy:      ${staticCsp.policy()}`);
  console.log(`Strict policy:      ${strictCsp.policy({ nonce: "example-nonce-1" })}`);
  console.log(`Report-only:        ${reportOnly.policy({ nonce: "example-nonce-1" })}`);
});

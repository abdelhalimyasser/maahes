# Examples

Runnable, end-to-end scripts that exercise the real built library
(`../dist/index.js`). Every script runs on **Node.js** and **Bun**:

```bash
npm run build                      # one-time: dist/ is gitignored
node examples/registration-login.mjs   # or: bun examples/registration-login.mjs
```

| Script | Demonstrates |
| --- | --- |
| [`registration-login.mjs`](registration-login.mjs) | Signup with policy rejection, uniform 401 login, silent hash upgrade via `verifyAndRehash` when parameters change |
| [`custom-policy.mjs`](custom-policy.mjs) | Full strict policy: class minimums, `minEntropy`, scripts, blocklist, custom rules, NFKC normalization, both enforcement surfaces |
| [`pepper-rotation.mjs`](pepper-rotation.mjs) | `$pepper$` markers, auto-pepper verification, legacy unmarked hashes, dual-verify rotation window with per-era secrets |
| [`migration-legacy.mjs`](migration-legacy.mjs) | Importing a plain-bcrypt store: `detectHashAlgorithm` routing, verify-any-bcrypt, on-login upgrade to Argon2id |
| [`cors-server.mjs`](cors-server.mjs) | CORS on real servers: raw `node:http` handler and a Connect-style chain — preflight, simple, denied, credentialed admin rule, `onBlock` |
| [`cors-fetch.mjs`](cors-fetch.mjs) | Web-standard `fetchHandler` bridged into an HTTP server: preflight interception, handler wrapping, callback-based origins |

All scripts are deterministic console demonstrations — each ends with a
`done - …` line when every step behaved as designed.
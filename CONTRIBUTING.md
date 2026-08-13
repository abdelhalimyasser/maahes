# Contributing to Maahes

Thanks for contributing! This document covers the process; the
engineering bar is in [docs/contributing.md](docs/contributing.md).

## Process

1. **Open an issue first** for anything beyond a one-line fix — design
   decisions (new options, new modules) need discussion before code.
2. **Fork, branch, work.** Use logical, conventional commits
   (`feat:` / `fix:` / `test:` / `docs:` / `chore:`) — one concern per
   commit. Don't push to `main`.
3. **Open a PR** against `main` with the template filled in. CI runs
   tests, typecheck, build, smoke checks on Node 18/20/22 + Bun, and
   `npm pack --dry-run`.
4. **Review** — maintainers review against the docs-as-contract rule:
   if behavior and docs disagree, the bug is on one side or the other.

## Security

- Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
- Never commit secrets, passwords, hashes or pepper material — not even
  in tests (tests use obviously-fake constants).

## Ground rules

- **Determinism is sacred.** Engines stay pure: fixed emission order,
  sorted output, no mutation of inputs, no ambient state. Frozen-input
  tests are part of the suite.
- **Fail fast on config, fail safe on input.** Option errors throw
  `MaahesOptionsError` subclasses at construction; verification of
  hostile input returns `false`, never throws or guesses.
- **Errors carry names and ranges, never values.** No passwords, hashes
  or pepper in error messages or logs.
- **Adapters are thin.** Middleware/fetch wrappers translate runtime
  objects to the pure engine; they never swallow downstream errors.
- **Three runtime deps max, and only when justified.** scrypt uses
  `node:crypto` precisely to avoid a native dependency.

## Development

```bash
bun install
bun test            # suite (3 modules, incl. adversarial)
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/ (ESM + CJS + d.ts)
npm run smoke:node  # built package under Node
npm run smoke:bun   # built package under Bun
```

## License

By contributing you agree that your contributions are licensed under
the MIT License (see [LICENSE](LICENSE)).
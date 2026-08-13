# Contributing

Thanks for contributing to Maahes. Read [CONTRIBUTING.md](../CONTRIBUTING.md)
for the process, and this file for the engineering bar.

## Conventions

- **Module layout** — each module owns its flat folder in `src/`:
  `{config,core,factory,errors,types,index}.ts` (plus module-specific
  files such as `drivers/`, `matchers.ts`, `middleware.ts`, `fetch.ts`).
- **Tests** live in `test/<module>/` — never inside `src/`.
- **Docstrings** — every public export carries a JSDoc `@module`/
  `@throws` note; no inline code comments unless they explain a *why*.
- **Errors** — extend `MaahesError` (option errors extend
  `MaahesOptionsError`); throw at construction, never in request paths.
- **Determinism** — engines must be pure: fixed emission order, sorted
  extras, no ambient state, no mutation of inputs (frozen inputs are a
  test case).
- **Adapters stay thin** — middleware/fetch wrappers only translate
  runtime objects to the pure engine; they must never swallow
  downstream errors.

## The bar for merging

1. `bun test` — green, including an **adversarial suite** for any new
   module (hostile inputs, boundary abuse, fail-closed paths,
   purity/determinism under frozen objects).
2. `npm run typecheck` — clean.
3. `npm run build` + `npm run smoke:node` + `npm run smoke:bun` — the
   built package works on both runtimes.
4. `npm pack --dry-run` — publish contents are what you intend
   (source maps, d.ts, both module formats; no tests/docs unless
   intentional).
5. Every new public option is documented in the module doc and reflected
   in `DEFAULT_*_CONFIG` + presets where applicable.
6. Examples update when behavior changes; the smoke script covers the
   new behavior.
7. Logical, conventional commits (`feat:`/`fix:`/`test:`/`docs:`/`chore:`)
   — one concern per commit, never pushed until asked.

## Reviewing

Use the docs as the contract: if behavior and docs disagree, the bug is
on one side or the other — pin it down in the review. Golden tests
(snapshot `build()`/`process()` output) are the fastest way to review
engine changes.
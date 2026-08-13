## Summary

<!-- What does this change do, and why? One paragraph. -->

## Type of change

<!-- Check one: -->

- [ ] Bug fix
- [ ] New feature / module
- [ ] Behavior change (documented in CHANGELOG)
- [ ] Docs / examples
- [ ] Tooling / CI
- [ ] Security hardening

## Verification

- [ ] `bun test` green (new behavior has tests; new modules have an
      adversarial suite)
- [ ] `npm run typecheck` clean
- [ ] `npm run build` + `npm run smoke:node` + `npm run smoke:bun` pass
- [ ] `npm pack --dry-run` shows the intended publish contents
- [ ] Docs updated where behavior/options changed
- [ ] Examples + smoke script cover the new behavior

## Security notes

<!-- For security-relevant changes: threat addressed, fail-closed paths,
secret handling, DoS bounds. For everything else: "No security impact." -->

## Checklist

- [ ] Logical, conventional commit messages (`feat:` / `fix:` / `test:` /
      `docs:` / `chore:`)
- [ ] No secrets, passwords, hashes or pepper material in code, logs or
      tests
- [ ] Deterministic output preserved (no ambient state, no input mutation)
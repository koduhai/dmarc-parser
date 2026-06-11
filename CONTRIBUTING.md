# Contributing to @koduhai/dmarc-parser

Thanks for your interest in improving this library. Bug reports, real-world DMARC
report samples that trip the parser, and pull requests are all welcome.

## Ground rules

- Be respectful and constructive in issues, pull requests, and discussions.
- Keep the scope tight: this package parses DMARC **aggregate (RUA)** reports into
  typed JSON. It is deliberately small and dependency-light. Features that pull in
  heavy dependencies or expand beyond aggregate-report parsing are likely out of scope,
  so please open an issue to discuss before building something large.

## Getting started

Requires Node.js >= 20 and npm.

```bash
git clone https://github.com/koduhai/dmarc-parser.git
cd dmarc-parser
npm ci
npm run check   # lint + format check + typecheck + tests, the same gate CI runs
```

## Development workflow

| Command | What it does |
|---|---|
| `npm test` | Run the test suite once |
| `npm run test:watch` | Re-run tests on change |
| `npm run test:coverage` | Run tests with a V8 coverage report |
| `npm run lint` | ESLint |
| `npm run format` | Apply Prettier formatting |
| `npm run format:check` | Verify formatting without writing |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run build` | Emit `dist/` |
| `npm run lint:package` | Validate the built package with publint + are-the-types-wrong (run after `build`) |
| `npm run check` | Everything CI checks, in one command |

Run `npm run check` before opening a PR. CI runs the same gate on Node 20, 22, and 24.

## Pull requests

1. Branch from `main`. Use a descriptive branch name (e.g. `fix/zip-entry-selection`).
2. Make focused, atomic commits with [Conventional Commit](https://www.conventionalcommits.org/)
   style subjects (`fix:`, `feat:`, `docs:`, `chore:`, `test:`, `refactor:`, ...).
3. Add or update tests for any behavior change. Parser changes especially should come
   with a test that captures the input that motivated them.
4. Update `README.md` and `CHANGELOG.md` when you change public behavior or the API.
5. Make sure `npm run check` passes.

## Reporting parsing bugs

DMARC reports vary by provider. If a real report does not parse correctly, the most
useful thing you can attach is a **minimized, anonymized** sample that reproduces the
problem (scrub real domains and IPs, keep the structure). Add it as a test case if you can.

## Releasing

Releases are published to npm by CI, not from a laptop. To cut a release (maintainers):

1. Bump the version and update `CHANGELOG.md`, then commit on `main`.
2. Tag it: `npm version <patch|minor|major>` creates a `vX.Y.Z` tag matching `package.json`.
3. `git push --follow-tags`.

Pushing the tag triggers `.github/workflows/release.yml`, which runs `npm run check`,
builds, verifies the tarball contents, and publishes to npm. The workflow fails if the
tag does not match the version in `package.json`.

Publishing uses npm [Trusted Publishing](https://docs.npmjs.com/trusted-publishers)
(OIDC) — there is no long-lived `NPM_TOKEN`. Provenance is generated automatically, so
the npm page links back to the exact commit and build. The package's trusted publisher
must be configured once on npm (GitHub Actions → repo `koduhai/dmarc-parser`, workflow
`release.yml`).

## Security

Please do not file security issues in the public tracker. See [SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](./LICENSE).

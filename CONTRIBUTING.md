# Contributing to @koduhai/dmarc-parser

Thanks for your interest in improving this library. Bug reports, real-world DMARC
report samples that trip the parser, and pull requests are all welcome.

## Ground rules

- Be respectful and constructive in issues, pull requests, and discussions. By
  participating you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).
- Keep the scope tight: this package parses DMARC **aggregate (RUA)** reports into
  typed JSON. It is deliberately small and dependency-light. Features that pull in
  heavy dependencies or expand beyond aggregate-report parsing are likely out of scope,
  so please open an issue to discuss before building something large.

## Getting started

Requires Node.js >= 20 and npm.

```bash
git clone https://github.com/koduhai/dmarc-parser.git
cd dmarc-parser
npm install
npm run check   # typecheck + lint + format:check + tests, the same gate CI runs
```

## Development workflow

| Command                 | What it does                                                          |
| ----------------------- | -------------------------------------------------------------------- |
| `npm test`              | Run the test suite once                                              |
| `npm run test:watch`    | Re-run tests on change                                               |
| `npm run test:coverage` | Run tests with coverage + thresholds                                 |
| `npm run lint`          | ESLint                                                               |
| `npm run format`        | Apply Prettier formatting                                            |
| `npm run format:check`  | Verify formatting without writing                                    |
| `npm run typecheck`     | `tsc --noEmit`                                                       |
| `npm run build`         | Emit `dist/`                                                         |
| `npm run check:exports` | Validate the published package (publint + attw); needs a build first |
| `npm run docs`          | Generate the TypeDoc API reference                                   |
| `npm run check`         | Everything CI checks, in one command                                 |

Run `npm run check` before opening a PR. CI runs the same gate on Node 20, 22, and 24.

## Pull requests

1. Branch from `main`. Use `<type>/<short-kebab-description>` (e.g. `fix/zip-entry-selection`).
2. Make focused, atomic commits (see Commit and PR conventions below).
3. Add or update tests for any behavior change. Parser changes especially should come
   with a test that captures the input that motivated them.
4. Update `README.md`, and add a `CHANGELOG.md` entry under `## [Unreleased]` if your
   change is user-visible (release-please otherwise manages the changelog).
5. Make sure `npm run check` passes.

## Commit and PR conventions

Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>: <imperative, lowercase summary>` (≤ 72 chars, no trailing period). Allowed types:

`feat` · `fix` · `chore` · `docs` · `refactor` · `perf` · `test` · `ci` · `build`

**The PR title matters most.** PRs are **squash-merged**, so the PR title becomes the single
commit on `main`, and [release-please](https://github.com/googleapis/release-please) turns
those commits into the version bump and `CHANGELOG.md` entry (`fix:` → patch, `feat:` → minor,
`feat!:` / `BREAKING CHANGE:` → major). It's enforced in two places:

- **PR title**: the _PR title_ CI check blocks a non-conforming title.
- **Locally**: a husky `commit-msg` hook runs commitlint on each commit (installed by
  `npm install`); bypass with `git commit --no-verify`. Local commits are squashed away.

Rules live in `commitlint.config.js`.

## Reporting parsing bugs

DMARC reports vary by provider. If a real report does not parse correctly, the most
useful thing you can attach is a **minimized, anonymized** sample that reproduces the
problem (scrub real domains and IPs, keep the structure). Add it as a test case if you can.

## Releasing

Releases are automated with [release-please](https://github.com/googleapis/release-please).
As conventional-commit PRs land on `main`, release-please maintains a "release PR" that bumps
the version and updates `CHANGELOG.md`. **Merging that release PR** creates the GitHub release
and tag, and the publish job then publishes to npm.

Publishing uses npm [Trusted Publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) —
there is no long-lived `NPM_TOKEN`, and provenance is generated automatically. The trusted
publisher is configured once on npm (GitHub Actions → repo `koduhai/dmarc-parser`, workflow
`release.yml`, environment `release`).

## Security

Please do not file security issues in the public tracker. See [SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](./LICENSE).

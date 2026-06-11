# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Parse the full `policy_published` record (`adkim`, `aspf`, `sp`, `np`, `fo`),
  `report_metadata` `<error>` entries, all DKIM/SPF `auth_results` (not just the
  first), and `policy_evaluated` override reasons. New fields on `DmarcReportMeta`
  and `DmarcRecord`, plus `DkimAuthResult`, `SpfAuthResult`, and `DmarcReason`.
- `summarize(report)` and `recordPassesDmarc(record)` helpers: message totals, an
  overall DMARC pass rate, and a per-source-IP rollup (`DmarcSummary`). The CLI now
  uses `summarize` and shows alignment/subdomain policy and override reasons.
- Provider-representative test fixtures (Google, Yahoo, Microsoft) under
  `src/__fixtures__/`.
- Linting and formatting tooling (ESLint 9 flat config, Prettier) plus a single
  `npm run check` gate.
- GitHub Actions CI across Node 20, 22, and 24; Dependabot for npm and Actions.
- `SECURITY.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`.
- Hardening against malicious report payloads: gzip and zip sizes are checked
  before inflation, raw XML is size-capped, and `DOCTYPE`/DTD input is rejected to
  close the entity-expansion vector.
- Non-numeric or negative `count` and `pct` values now coerce to safe defaults.

### Changed

- Minimum supported Node.js raised to 20.
- Bumped `fast-xml-parser` to 5.x and `vitest` to 4.x.

## [0.1.0]

### Added

- Initial release: DMARC aggregate (RUA) report parser with a CLI and library.
- Parse raw `.xml`, gzipped `.xml.gz`, zipped `.zip`, and `.eml` MIME emails into
  typed JSON.

[Unreleased]: https://github.com/koduhai/dmarc-parser/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/koduhai/dmarc-parser/releases/tag/v0.1.0

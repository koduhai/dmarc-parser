# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0](https://github.com/koduhai/dmarc-parser/compare/dmarc-parser-v0.2.0...dmarc-parser-v0.3.0) (2026-06-11)


### Features

* add aggregate() and continuous packaging checks (v0.2.0) ([e77cfa0](https://github.com/koduhai/dmarc-parser/commit/e77cfa087690b435e87e5a0e67001e7138881b91))
* aggregate() API + continuous packaging checks (v0.2.0) ([3512d2c](https://github.com/koduhai/dmarc-parser/commit/3512d2c87c53af475e45cc2edc7c4d98b767b25a))
* DMARC aggregate report parser (CLI + library) ([d353554](https://github.com/koduhai/dmarc-parser/commit/d353554ded12f5ca030e2dd5817e398fc755ce76))


### Bug Fixes

* pin ossf/scorecard-action to v2.4.3 ([80d9a8e](https://github.com/koduhai/dmarc-parser/commit/80d9a8e183c05dfacaab4ab46155ee56c983553d))
* pin ossf/scorecard-action to v2.4.3 ([7ae9b50](https://github.com/koduhai/dmarc-parser/commit/7ae9b509d1aa366751be95b9b135385e744a8031))
* truncate counts to integers and clamp pct to 100 ([2ec31a5](https://github.com/koduhai/dmarc-parser/commit/2ec31a521e268e5babcd7be84ddb0394767fb48b))
* truncate counts to integers and clamp pct to 100 (v0.1.1) ([722e47c](https://github.com/koduhai/dmarc-parser/commit/722e47c47087c19136e5a360753e2c13187b381c))

## [0.2.0] - 2026-06-11

### Added

- `aggregate(reports)` → `DmarcAggregate`: combine many reports into one rollup —
  message totals, overall pass rate, a per-source-IP breakdown spanning every
  report, the covered date window, and the distinct policy domains. Useful for
  rolling up a mailbox or storage prefix of daily reports over a date range. The
  CLI's `--fail-under` gate now uses it.
- Continuous packaging checks: `npm run lint:package` runs
  [publint](https://publint.dev) and [are-the-types-wrong](https://arethetypeswrong.github.io)
  against the built tarball, and CI enforces them.

## [0.1.1] - 2026-06-11

### Fixed

- `count` (and other numeric fields) now truncate to a non-negative integer rather
  than passing through fractional values, and `policyPct` is clamped to a maximum of
  100. Malformed numbers continue to coerce to safe defaults.

## [0.1.0] - 2026-06-10

Initial release.

### Added

- Parse DMARC aggregate (RUA) reports from raw `.xml`, gzipped `.xml.gz`, zipped
  `.zip`, or a whole `.eml` MIME email into one typed `DmarcReport`.
- Full report coverage: `policy_published` (`p`, `sp`, `pct`, `adkim`, `aspf`, `np`,
  `fo`), `report_metadata` `<error>` entries, all DKIM/SPF `auth_results`, and
  `policy_evaluated` override reasons. Types: `DmarcReport`, `DmarcReportMeta`,
  `DmarcRecord`, `DkimAuthResult`, `SpfAuthResult`, `DmarcReason`, `DmarcSummary`.
- `summarize(report)` and `recordPassesDmarc(record)` helpers: message totals, an
  overall DMARC pass rate, and a per-source-IP rollup.
- CLI: human summary plus `--json`, `--ndjson`, and `--csv` output; multiple files;
  a `--fail-under <n>` gate (exit 3 when the combined pass rate is too low); and
  stdin auto-detection of xml/gz/zip/eml.

### Security

- Bounded against decompression bombs: gzip and zip sizes are checked before
  inflation, raw XML is size-capped (50 MB), and non-`.xml` zip entries are never
  expanded.
- `DOCTYPE`/DTD input is rejected, closing the entity-expansion ("billion laughs")
  vector. The underlying parser does not resolve external entities, so XXE is not
  reachable.
- On any input the parser and `decompressReport` either return well-formed output or
  throw a typed `DmarcParseError`, verified by `fast-check` property/fuzz tests.
  Non-numeric or negative `count`/`pct` values coerce to safe defaults.

[0.2.0]: https://github.com/koduhai/dmarc-parser/releases/tag/v0.2.0
[0.1.1]: https://github.com/koduhai/dmarc-parser/releases/tag/v0.1.1
[0.1.0]: https://github.com/koduhai/dmarc-parser/releases/tag/v0.1.0

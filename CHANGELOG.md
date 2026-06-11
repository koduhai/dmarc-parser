# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/koduhai/dmarc-parser/releases/tag/v0.1.0

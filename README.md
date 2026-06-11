# @koduhai/dmarc-parser

[![CI](https://github.com/koduhai/dmarc-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/koduhai/dmarc-parser/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@koduhai/dmarc-parser)](https://www.npmjs.com/package/@koduhai/dmarc-parser)
[![node](https://img.shields.io/node/v/@koduhai/dmarc-parser)](https://nodejs.org)
[![license: MIT](https://img.shields.io/npm/l/@koduhai/dmarc-parser)](./LICENSE)

Parse **DMARC aggregate (RUA) reports** into typed JSON, from any form mailbox providers
send them in: raw `.xml`, gzipped `.xml.gz`, zipped `.zip`, or a whole `.eml` MIME email.
Ships a zero-config CLI and a tiny, dependency-light library. No service, no account, runs
fully offline.

```
$ dmarc-parser google.com!example.com!1717.xml.gz

  DMARC aggregate report  #RID-12345
  domain    example.com
  reporter  google.com
  window    2024-06-01 → 2024-06-02
  policy    p=quarantine pct=100

  DMARC pass rate  71.4%   (5/7 messages)

  source ip    count  dkim  spf   disposition
  203.0.113.1      5  pass  pass   none
  198.51.100.7     2  fail  pass   quarantine
```

## Why

Every mailbox provider (Google, Yahoo, Microsoft, ...) emails you DMARC aggregate reports as
gzipped XML buried inside a MIME message. The format is awkward: array-vs-single `<record>`
quirks, compressed attachments, inconsistent fields. This turns the whole mess into one typed
object (or a readable summary) in a single call, so you can actually see who is sending mail as
your domain and whether it is passing authentication.

## Install

```bash
# CLI (no install)
npx @koduhai/dmarc-parser report.xml.gz

# or as a library
npm install @koduhai/dmarc-parser
```

## CLI

```bash
dmarc-parser <file>...        # one or more .xml, .xml.gz, .gz, .zip, or .eml files
dmarc-parser report.eml --json
dmarc-parser reports/*.xml.gz --csv > reports.csv
cat report.xml | dmarc-parser -          # stdin auto-detects xml / gz / zip / eml
dmarc-parser reports/*.gz --fail-under 95   # gate a CI job on deliverability
```

| Flag | Effect |
|---|---|
| `--json` | Print parsed report(s) as pretty JSON (an array when given multiple files) |
| `--ndjson` | Print one compact JSON report per line (stream-friendly) |
| `--csv` | Print one CSV row per record across all inputs |
| `--fail-under <n>` | Exit `3` if the combined DMARC pass rate is below `n` percent |
| `-h`, `--help` | Show usage |

Exit codes: `0` ok · `1` parse/read error · `2` usage error · `3` pass rate below `--fail-under`.

## Library

```ts
import {
  parseDmarcXml,     // (xml: string) => DmarcReport            — pure, sync
  decompressReport,  // (filename, bytes: Uint8Array) => string — .gz/.zip/.xml -> xml
  extractReportXml,  // (rawMime) => Promise<string>            — pull xml out of a MIME email
  parseReportEmail,  // (rawMime) => Promise<DmarcReport>       — extract + parse in one call
  summarize,         // (report) => DmarcSummary                — totals, pass rate, per-IP rollup
  recordPassesDmarc, // (record) => boolean                     — true if DKIM or SPF is aligned-pass
  DmarcParseError,
} from '@koduhai/dmarc-parser';

import { readFileSync } from 'node:fs';

// From a raw report email (e.g. an S3 object or an IMAP fetch):
const report = await parseReportEmail(readFileSync('report.eml'));

console.log(report.meta.domain, report.meta.orgName);
for (const r of report.records) {
  console.log(r.sourceIp, r.count, recordPassesDmarc(r) ? 'PASS' : 'FAIL');
}

// Or skip the manual loop and get totals + a per-source-IP breakdown:
const { total, passing, passRate, bySourceIp } = summarize(report);
console.log(`${passRate}% pass (${passing}/${total})`);
```

### Types

```ts
interface DmarcReport {
  meta: DmarcReportMeta;
  records: DmarcRecord[];
}

interface DmarcReportMeta {
  orgName: string;            // reporting org, e.g. "google.com"
  reportId: string;           // unique id (use for idempotent ingestion)
  domain: string;             // domain the policy applies to
  dateBegin: Date;
  dateEnd: Date;
  policyP: string | null;     // "none" | "quarantine" | "reject"
  policySp: string | null;    // subdomain policy
  policyPct: number | null;
  policyAdkim: string | null; // DKIM alignment: "r" | "s"
  policyAspf: string | null;  // SPF alignment: "r" | "s"
  policyNp: string | null;    // policy for non-existent subdomains
  policyFo: string | null;    // failure-reporting options
  errors: string[];           // <error> entries the reporter included
}

interface DmarcRecord {
  sourceIp: string;
  count: number;
  disposition: string | null;  // applied: none | quarantine | reject
  dkimResult: string | null;   // DMARC-aligned, from policy_evaluated
  spfResult: string | null;    // DMARC-aligned, from policy_evaluated
  headerFrom: string | null;
  dkimDomain: string | null;   // primary (first) DKIM-authenticated domain
  spfDomain: string | null;    // primary (first) SPF-authenticated domain
  dkimAuth: DkimAuthResult[];  // all DKIM signatures: { domain, selector, result }
  spfAuth: SpfAuthResult[];    // all SPF results:     { domain, scope, result }
  reasons: DmarcReason[];      // policy_evaluated overrides: { type, comment }
}

interface DmarcSummary {
  total: number;               // total messages across all records
  passing: number;
  failing: number;
  passRate: number;            // 0-100, one decimal
  bySourceIp: { sourceIp: string; count: number; passing: number; passRate: number }[];
}
```

A message **passes DMARC** when at least one aligned mechanism (DKIM or SPF) passes, i.e.
`dkimResult === 'pass' || spfResult === 'pass'` (this is exactly what `recordPassesDmarc`
and `summarize` use).

## Notes

- **Safe by default.** Decompressed payloads are capped (50 MB) to bound decompression-bomb
  attachments, and malformed input throws a typed `DmarcParseError` rather than returning
  garbage.
- **ESM only**, Node ≥ 20. Three small dependencies (`fast-xml-parser`, `fflate`, `mailparser`).
- Aggregate (RUA) reports only. Failure (RUF) reports are a different, rarer format.

## License

MIT © [Koduhai](https://github.com/koduhai). Built and maintained alongside
[KoduhMail](https://koduhmail.com), an email API with first-class deliverability tooling.

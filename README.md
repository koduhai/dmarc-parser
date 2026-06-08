# @koduhai/dmarc-parser

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
dmarc-parser <file>     # .xml, .xml.gz, .gz, .zip, or .eml
dmarc-parser report.eml --json
cat report.xml | dmarc-parser -
```

| Flag | Effect |
|---|---|
| `--json` | Print the parsed report as JSON instead of the summary |
| `-h`, `--help` | Show usage |

Exit codes: `0` ok · `1` parse/read error · `2` usage error.

## Library

```ts
import {
  parseDmarcXml,     // (xml: string) => DmarcReport            — pure, sync
  decompressReport,  // (filename, bytes: Uint8Array) => string — .gz/.zip/.xml -> xml
  extractReportXml,  // (rawMime) => Promise<string>            — pull xml out of a MIME email
  parseReportEmail,  // (rawMime) => Promise<DmarcReport>       — extract + parse in one call
  DmarcParseError,
} from '@koduhai/dmarc-parser';

import { readFileSync } from 'node:fs';

// From a raw report email (e.g. an S3 object or an IMAP fetch):
const report = await parseReportEmail(readFileSync('report.eml'));

console.log(report.meta.domain, report.meta.orgName);
for (const r of report.records) {
  const dmarcPass = r.dkimResult === 'pass' || r.spfResult === 'pass';
  console.log(r.sourceIp, r.count, dmarcPass ? 'PASS' : 'FAIL');
}
```

### Types

```ts
interface DmarcReport {
  meta: DmarcReportMeta;
  records: DmarcRecord[];
}

interface DmarcReportMeta {
  orgName: string;        // reporting org, e.g. "google.com"
  reportId: string;       // unique id (use for idempotent ingestion)
  domain: string;         // domain the policy applies to
  dateBegin: Date;
  dateEnd: Date;
  policyP: string | null; // "none" | "quarantine" | "reject"
  policyPct: number | null;
}

interface DmarcRecord {
  sourceIp: string;
  count: number;
  disposition: string | null;  // applied: none | quarantine | reject
  dkimResult: string | null;   // DMARC-aligned, from policy_evaluated
  spfResult: string | null;    // DMARC-aligned, from policy_evaluated
  headerFrom: string | null;
  dkimDomain: string | null;
  spfDomain: string | null;
}
```

A message **passes DMARC** when at least one aligned mechanism (DKIM or SPF) passes, i.e.
`dkimResult === 'pass' || spfResult === 'pass'`.

## Notes

- **Safe by default.** Decompressed payloads are capped (50 MB) to bound decompression-bomb
  attachments, and malformed input throws a typed `DmarcParseError` rather than returning
  garbage.
- **ESM only**, Node ≥ 18. Three small dependencies (`fast-xml-parser`, `fflate`, `mailparser`).
- Aggregate (RUA) reports only. Failure (RUF) reports are a different, rarer format.

## License

MIT © [Koduhai](https://github.com/koduhai). Built and maintained alongside
[KoduhMail](https://koduhmail.com), an email API with first-class deliverability tooling.

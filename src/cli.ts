#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  parseDmarcXml,
  decompressReport,
  extractReportXml,
  summarize,
  DmarcParseError,
  type DmarcReport,
} from './parse.js';

const USAGE = `dmarc-parser — parse DMARC aggregate (RUA) reports into a readable summary, JSON, or CSV.

Usage:
  dmarc-parser <file>...         Parse one or more report files (.xml, .xml.gz, .gz, .zip, or .eml)
  dmarc-parser -                 Read a single report from stdin (auto-detects xml/gz/zip/eml)
  cat report.xml | dmarc-parser -

Options:
  --json              Print parsed report(s) as pretty JSON (an array when given multiple files)
  --ndjson            Print one compact JSON report per line (stream-friendly)
  --csv               Print one CSV row per record across all inputs
  --fail-under <n>    Exit 3 if the combined DMARC pass rate is below n percent (0-100)
  -h, --help          Show this help

Exit codes: 0 ok · 1 parse/read error · 2 usage error · 3 pass rate below --fail-under.

Examples:
  dmarc-parser google.com!example.com!1717.xml.gz
  dmarc-parser reports/*.xml.gz --csv > reports.csv
  dmarc-parser report.eml --json
  dmarc-parser reports/*.gz --fail-under 95   # gate a CI job on deliverability
`;

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s: string) => c('1', s);
const dim = (s: string) => c('2', s);
const green = (s: string) => c('32', s);
const red = (s: string) => c('31', s);
const yellow = (s: string) => c('33', s);

function readStdin(): Buffer {
  try {
    return readFileSync(0); // fd 0 = stdin
  } catch {
    return Buffer.alloc(0);
  }
}

// Heuristic: does this look like a raw MIME email rather than XML or an archive? Checks for a
// leading RFC 5322 header line, the form mailbox providers wrap aggregate reports in.
function looksLikeMime(bytes: Buffer): boolean {
  const head = bytes.subarray(0, 1024).toString('latin1');
  if (head.trimStart().startsWith('<')) return false; // raw XML
  return /^(from|to|subject|date|received|return-path|message-id|delivered-to|mime-version|content-type|dkim-signature):/im.test(
    head,
  );
}

async function loadReport(arg: string): Promise<DmarcReport> {
  const bytes = arg === '-' ? readStdin() : readFileSync(arg);
  if (bytes.length === 0) throw new DmarcParseError('no input received');
  const lower = arg.toLowerCase();
  if (lower.endsWith('.eml') || lower.endsWith('.email')) {
    return parseDmarcXml(await extractReportXml(bytes));
  }
  // stdin has no extension: a raw email needs MIME extraction, everything else (xml/gz/zip) is
  // handled by decompressReport's magic-byte sniffing.
  if (arg === '-' && looksLikeMime(bytes)) {
    return parseDmarcXml(await extractReportXml(bytes));
  }
  return parseDmarcXml(decompressReport(arg === '-' ? 'stdin' : arg, new Uint8Array(bytes)));
}

function passmark(result: string | null): string {
  if (result === 'pass') return green('pass');
  if (result === 'fail') return red('fail');
  return dim(result ?? '-');
}

function printSummary(r: DmarcReport): void {
  const { total, passing, passRate } = summarize(r);
  const rateStr =
    passRate >= 95 ? green(`${passRate}%`) : passRate >= 80 ? yellow(`${passRate}%`) : red(`${passRate}%`);

  // Compact policy line: only show fields the report actually published.
  const policyBits = [
    `p=${r.meta.policyP ?? 'none'}`,
    r.meta.policySp != null ? `sp=${r.meta.policySp}` : '',
    r.meta.policyAdkim != null ? `adkim=${r.meta.policyAdkim}` : '',
    r.meta.policyAspf != null ? `aspf=${r.meta.policyAspf}` : '',
    r.meta.policyPct != null ? `pct=${r.meta.policyPct}` : '',
  ].filter(Boolean);

  const span = `${r.meta.dateBegin.toISOString().slice(0, 10)} → ${r.meta.dateEnd.toISOString().slice(0, 10)}`;

  console.log('');
  console.log(`  ${bold('DMARC aggregate report')}  ${dim(`#${r.meta.reportId}`)}`);
  console.log(`  ${dim('domain')}    ${bold(r.meta.domain || '(none)')}`);
  console.log(`  ${dim('reporter')}  ${r.meta.orgName}`);
  console.log(`  ${dim('window')}    ${span}`);
  console.log(`  ${dim('policy')}    ${policyBits.join(' ')}`);
  console.log('');
  console.log(`  ${bold('DMARC pass rate')}  ${rateStr}   ${dim(`(${passing}/${total} messages)`)}`);
  console.log('');

  const ipW = Math.max(9, ...r.records.map((rec) => rec.sourceIp.length));
  console.log(
    `  ${dim('source ip'.padEnd(ipW))}  ${dim('count'.padStart(6))}  ${dim('dkim')}  ${dim('spf')}   ${dim('disposition')}`,
  );
  for (const rec of r.records) {
    const reasonTypes = rec.reasons.map((x) => x.type).filter(Boolean);
    const reason = reasonTypes.length ? dim(` (${reasonTypes.join(', ')})`) : '';
    console.log(
      `  ${rec.sourceIp.padEnd(ipW)}  ${String(rec.count).padStart(6)}  ${passmark(rec.dkimResult)}  ${passmark(rec.spfResult)}   ${rec.disposition ?? '-'}${reason}`,
    );
  }
  console.log('');
}

const CSV_HEADER = [
  'file',
  'report_id',
  'org_name',
  'domain',
  'date_begin',
  'date_end',
  'source_ip',
  'count',
  'disposition',
  'dkim',
  'spf',
  'header_from',
] as const;

// Quote a CSV cell only when it contains a comma, quote, or newline (RFC 4180).
function csvCell(v: string | number | null): string {
  const s = v == null ? '' : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function printCsv(loaded: { file: string; report: DmarcReport }[]): void {
  const lines = [CSV_HEADER.join(',')];
  for (const { file, report } of loaded) {
    for (const rec of report.records) {
      lines.push(
        [
          file,
          report.meta.reportId,
          report.meta.orgName,
          report.meta.domain,
          report.meta.dateBegin.toISOString(),
          report.meta.dateEnd.toISOString(),
          rec.sourceIp,
          rec.count,
          rec.disposition,
          rec.dkimResult,
          rec.spfResult,
          rec.headerFrom,
        ]
          .map(csvCell)
          .join(','),
      );
    }
  }
  console.log(lines.join('\n'));
}

// Combined pass rate across every input report (totals summed, then divided once).
function combinedPassRate(reports: DmarcReport[]): { total: number; passing: number; passRate: number } {
  let total = 0;
  let passing = 0;
  for (const report of reports) {
    const s = summarize(report);
    total += s.total;
    passing += s.passing;
  }
  return { total, passing, passRate: total === 0 ? 0 : Math.round((passing / total) * 1000) / 10 };
}

interface CliOptions {
  format: 'summary' | 'json' | 'ndjson' | 'csv';
  failUnder: number | null;
  files: string[];
}

// Returns parsed options, or a numeric exit code when the args are unusable.
function parseArgs(args: string[]): CliOptions | number {
  let format: CliOptions['format'] = 'summary';
  let formatSet = false;
  let failUnder: number | null = null;
  const files: string[] = [];

  const setFormat = (f: CliOptions['format']): boolean => {
    if (formatSet && format !== f) {
      console.error('error: choose only one of --json, --ndjson, --csv');
      return false;
    }
    format = f;
    formatSet = true;
    return true;
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json' || a === '--ndjson' || a === '--csv') {
      if (!setFormat(a.slice(2) as CliOptions['format'])) return 2;
    } else if (a === '--fail-under' || a.startsWith('--fail-under=')) {
      const raw = a.includes('=') ? a.slice(a.indexOf('=') + 1) : args[++i];
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 0 || n > 100) {
        console.error('error: --fail-under requires a number between 0 and 100');
        return 2;
      }
      failUnder = n;
    } else if (a === '-' || !a.startsWith('-')) {
      files.push(a);
    } else {
      console.error(`error: unknown option ${a}`);
      return 2;
    }
  }

  if (files.length === 0) {
    console.error('error: no input file given (use - for stdin)');
    return 2;
  }
  if (files.length > 1 && files.includes('-')) {
    console.error('error: stdin (-) cannot be combined with other files');
    return 2;
  }
  return { format, failUnder, files };
}

export async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    console.log(USAGE);
    return args.length === 0 ? 2 : 0;
  }

  const opts = parseArgs(args);
  if (typeof opts === 'number') return opts;

  const loaded: { file: string; report: DmarcReport }[] = [];
  try {
    for (const file of opts.files) {
      loaded.push({ file, report: await loadReport(file) });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`${red('error')}: ${msg}`);
    return 1;
  }

  if (opts.format === 'csv') {
    printCsv(loaded);
  } else if (opts.format === 'ndjson') {
    for (const { report } of loaded) console.log(JSON.stringify(report));
  } else if (opts.format === 'json') {
    const out = loaded.length === 1 ? loaded[0].report : loaded.map((l) => l.report);
    console.log(JSON.stringify(out, null, 2));
  } else {
    for (const { file, report } of loaded) {
      if (loaded.length > 1) console.log(dim(`# ${file}`));
      printSummary(report);
    }
  }

  if (opts.failUnder != null) {
    const { total, passing, passRate } = combinedPassRate(loaded.map((l) => l.report));
    if (passRate < opts.failUnder) {
      console.error(
        `${red('fail')}: DMARC pass rate ${passRate}% (${passing}/${total}) is below the --fail-under threshold of ${opts.failUnder}%`,
      );
      return 3;
    }
  }
  return 0;
}

// Run only when invoked directly, so tests can import main() without triggering process.exit.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv).then((code) => process.exit(code));
}

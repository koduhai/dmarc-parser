#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseDmarcXml, decompressReport, extractReportXml, DmarcParseError, type DmarcReport } from './parse.js';

const USAGE = `dmarc-parser — parse a DMARC aggregate (RUA) report into a readable summary or JSON.

Usage:
  dmarc-parser <file>            Parse a report file (.xml, .xml.gz, .gz, .zip, or .eml)
  dmarc-parser -                 Read the report from stdin
  cat report.xml | dmarc-parser -

Options:
  --json        Print the parsed report as JSON instead of a summary
  -h, --help    Show this help

Examples:
  dmarc-parser google.com!example.com!1717.xml.gz
  dmarc-parser report.eml --json
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

async function loadReport(arg: string): Promise<DmarcReport> {
  const bytes = arg === '-' ? readStdin() : readFileSync(arg);
  if (bytes.length === 0) throw new DmarcParseError('no input received');
  const lower = arg.toLowerCase();
  if (lower.endsWith('.eml') || lower.endsWith('.email')) {
    return parseDmarcXml(await extractReportXml(bytes));
  }
  // For stdin, pass a neutral name so decompressReport sniffs the magic bytes.
  return parseDmarcXml(decompressReport(arg === '-' ? 'stdin' : arg, new Uint8Array(bytes)));
}

function passmark(result: string | null): string {
  if (result === 'pass') return green('pass');
  if (result === 'fail') return red('fail');
  return dim(result ?? '-');
}

function printSummary(r: DmarcReport): void {
  const total = r.records.reduce((n, rec) => n + rec.count, 0);
  // A message passes DMARC when at least one aligned mechanism (DKIM or SPF) passes.
  const passing = r.records
    .filter((rec) => rec.dkimResult === 'pass' || rec.spfResult === 'pass')
    .reduce((n, rec) => n + rec.count, 0);
  const rate = total === 0 ? 0 : Math.round((passing / total) * 1000) / 10;
  const rateStr = rate >= 95 ? green(`${rate}%`) : rate >= 80 ? yellow(`${rate}%`) : red(`${rate}%`);

  const span = `${r.meta.dateBegin.toISOString().slice(0, 10)} → ${r.meta.dateEnd.toISOString().slice(0, 10)}`;

  console.log('');
  console.log(`  ${bold('DMARC aggregate report')}  ${dim(`#${r.meta.reportId}`)}`);
  console.log(`  ${dim('domain')}    ${bold(r.meta.domain || '(none)')}`);
  console.log(`  ${dim('reporter')}  ${r.meta.orgName}`);
  console.log(`  ${dim('window')}    ${span}`);
  console.log(`  ${dim('policy')}    p=${r.meta.policyP ?? 'none'}${r.meta.policyPct != null ? ` pct=${r.meta.policyPct}` : ''}`);
  console.log('');
  console.log(`  ${bold('DMARC pass rate')}  ${rateStr}   ${dim(`(${passing}/${total} messages)`)}`);
  console.log('');

  const ipW = Math.max(9, ...r.records.map((rec) => rec.sourceIp.length));
  console.log(`  ${dim('source ip'.padEnd(ipW))}  ${dim('count'.padStart(6))}  ${dim('dkim')}  ${dim('spf')}   ${dim('disposition')}`);
  for (const rec of r.records) {
    console.log(
      `  ${rec.sourceIp.padEnd(ipW)}  ${String(rec.count).padStart(6)}  ${passmark(rec.dkimResult)}  ${passmark(rec.spfResult)}   ${rec.disposition ?? '-'}`,
    );
  }
  console.log('');
}

export async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    console.log(USAGE);
    return args.length === 0 ? 2 : 0;
  }
  const asJson = args.includes('--json');
  const file = args.find((a) => a === '-' || !a.startsWith('--'));
  if (!file) {
    console.error('error: no input file given (use - for stdin)');
    return 2;
  }
  try {
    const report = await loadReport(file);
    if (asJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printSummary(report);
    }
    return 0;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`${red('error')}: ${msg}`);
    return 1;
  }
}

main(process.argv).then((code) => process.exit(code));

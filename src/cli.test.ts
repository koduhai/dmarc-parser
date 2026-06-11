import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from './cli.js';

const PASS_XML = `<?xml version="1.0"?><feedback>
  <report_metadata><org_name>google.com</org_name><report_id>RID-PASS</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p><pct>100</pct></policy_published>
  <record><row><source_ip>203.0.113.1</source_ip><count>10</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers></record>
</feedback>`;

// Two records, one passing and one failing the same count -> 50% combined pass rate.
const MIXED_XML = `<?xml version="1.0"?><feedback>
  <report_metadata><org_name>yahoo.com</org_name><report_id>RID-MIX</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record><row><source_ip>198.51.100.1</source_ip><count>1</count>
    <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
  <record><row><source_ip>198.51.100.2</source_ip><count>1</count>
    <policy_evaluated><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record>
</feedback>`;

let dir: string;
let out: string[];
let err: string[];

function argv(...args: string[]): string[] {
  return ['node', 'cli.js', ...args];
}
const stdout = (): string => out.join('\n');
const stderr = (): string => err.join('\n');

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dmarc-cli-'));
  out = [];
  err = [];
  vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')));
  vi.spyOn(console, 'error').mockImplementation((...a) => void err.push(a.join(' ')));
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

function write(name: string, xml: string): string {
  const p = join(dir, name);
  writeFileSync(p, xml, 'utf8');
  return p;
}

describe('cli argument handling', () => {
  it('prints usage and exits 2 with no args', async () => {
    expect(await main(argv())).toBe(2);
    expect(stdout()).toContain('Usage:');
  });

  it('prints usage and exits 0 on --help', async () => {
    expect(await main(argv('--help'))).toBe(0);
    expect(stdout()).toContain('Usage:');
  });

  it('exits 2 on an unknown option', async () => {
    expect(await main(argv('--nope', write('r.xml', PASS_XML)))).toBe(2);
    expect(stderr()).toContain('unknown option');
  });

  it('exits 2 when two output formats are combined', async () => {
    expect(await main(argv('--json', '--csv', write('r.xml', PASS_XML)))).toBe(2);
  });

  it('exits 2 when stdin is combined with a file', async () => {
    expect(await main(argv('-', write('r.xml', PASS_XML)))).toBe(2);
  });

  it('exits 1 on a missing file', async () => {
    expect(await main(argv(join(dir, 'does-not-exist.xml')))).toBe(1);
    expect(stderr()).toContain('error');
  });
});

describe('cli output formats', () => {
  it('prints a human summary by default', async () => {
    expect(await main(argv(write('r.xml', PASS_XML)))).toBe(0);
    expect(stdout()).toContain('DMARC aggregate report');
    expect(stdout()).toContain('100%');
  });

  it('--json emits a single object for one file', async () => {
    expect(await main(argv('--json', write('r.xml', PASS_XML)))).toBe(0);
    const parsed = JSON.parse(stdout());
    expect(parsed.meta.reportId).toBe('RID-PASS');
    expect(Array.isArray(parsed)).toBe(false);
  });

  it('--json emits an array for multiple files', async () => {
    const code = await main(argv('--json', write('a.xml', PASS_XML), write('b.xml', MIXED_XML)));
    expect(code).toBe(0);
    const parsed = JSON.parse(stdout());
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.map((r: { meta: { reportId: string } }) => r.meta.reportId)).toEqual([
      'RID-PASS',
      'RID-MIX',
    ]);
  });

  it('--ndjson emits one JSON report per line', async () => {
    await main(argv('--ndjson', write('a.xml', PASS_XML), write('b.xml', MIXED_XML)));
    const lines = stdout().split('\n').filter(Boolean);
    expect(lines).toHaveLength(2);
    expect(lines.map((l) => JSON.parse(l).meta.reportId)).toEqual(['RID-PASS', 'RID-MIX']);
  });

  it('--csv emits a header and one row per record', async () => {
    await main(argv('--csv', write('r.xml', MIXED_XML)));
    const lines = stdout().split('\n').filter(Boolean);
    expect(lines[0]).toBe(
      'file,report_id,org_name,domain,date_begin,date_end,source_ip,count,disposition,dkim,spf,header_from',
    );
    expect(lines).toHaveLength(3); // header + 2 records
    expect(lines[1]).toContain('198.51.100.1');
    expect(lines[2]).toContain('RID-MIX');
  });
});

describe('cli --fail-under gate', () => {
  it('exits 3 when the combined pass rate is below the threshold', async () => {
    expect(await main(argv('--fail-under', '95', write('r.xml', MIXED_XML)))).toBe(3);
    expect(stderr()).toContain('below the --fail-under threshold');
  });

  it('exits 0 when the combined pass rate meets the threshold', async () => {
    expect(await main(argv('--fail-under', '40', write('r.xml', MIXED_XML)))).toBe(0);
  });

  it('aggregates the rate across multiple files', async () => {
    // PASS (10/10) + MIXED (1/2) = 11/12 = 91.7% -> below 95, at/above 90.
    expect(await main(argv('--fail-under=95', write('a.xml', PASS_XML), write('b.xml', MIXED_XML)))).toBe(3);
    expect(await main(argv('--fail-under=90', write('a.xml', PASS_XML), write('b.xml', MIXED_XML)))).toBe(0);
  });

  it('rejects a non-numeric threshold with exit 2', async () => {
    expect(await main(argv('--fail-under', 'abc', write('r.xml', PASS_XML)))).toBe(2);
  });
});

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseDmarcXml, summarize } from './parse.js';

const fixture = (name: string): string =>
  readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf8');

describe('real-world provider fixtures', () => {
  it('google.xml: baseline single-record report with full policy', () => {
    const r = parseDmarcXml(fixture('google.xml'));
    expect(r.meta.orgName).toBe('google.com');
    expect(r.meta.policyP).toBe('reject');
    expect(r.meta.policySp).toBe('reject');
    expect(r.meta.policyAdkim).toBe('r');
    expect(r.meta.policyAspf).toBe('r');
    expect(r.meta.policyPct).toBe(100);

    expect(r.records).toHaveLength(1);
    expect(r.records[0].dkimAuth).toHaveLength(1);
    expect(r.records[0].dkimAuth[0]).toMatchObject({
      domain: 'example.com',
      selector: 'google',
      result: 'pass',
    });
    expect(r.records[0].dkimDomain).toBe('example.com');

    const s = summarize(r);
    expect(s).toMatchObject({ total: 128, passing: 128, failing: 0, passRate: 100 });
  });

  it('yahoo.xml: array of records and SPF scope', () => {
    const r = parseDmarcXml(fixture('yahoo.xml'));
    expect(r.meta.orgName).toBe('Yahoo');
    expect(r.meta.policyAdkim).toBe('s');
    expect(r.records).toHaveLength(2);
    expect(r.records[0].spfAuth[0]).toMatchObject({ domain: 'example.com', scope: 'mfrom', result: 'pass' });

    const s = summarize(r);
    // Row 0 passes via SPF (9), row 1 passes via DKIM (4): all 13 pass DMARC.
    expect(s).toMatchObject({ total: 13, passing: 13, passRate: 100 });
    // bySourceIp is sorted by message count, descending.
    expect(s.bySourceIp.map((b) => b.sourceIp)).toEqual(['198.51.100.7', '198.51.100.23']);
    expect(s.bySourceIp[0]).toMatchObject({ count: 9, passing: 9, passRate: 100 });
  });

  it('microsoft.xml: multiple DKIM signatures, override reason, and metadata error', () => {
    const r = parseDmarcXml(fixture('microsoft.xml'));
    expect(r.meta.errors).toContain('Some records were sampled.');
    expect(r.meta.policyFo).toBe('1');
    expect(r.meta.policySp).toBe('none');

    const rec = r.records[0];
    expect(rec.dkimAuth).toHaveLength(2);
    expect(rec.dkimAuth.map((d) => d.domain)).toEqual(['example.com', 'list.example.org']);
    expect(rec.reasons).toEqual([{ type: 'forwarded', comment: 'mailing list' }]);
    // dkim pass + spf fail still passes DMARC (one aligned mechanism is enough).
    expect(rec.dkimResult).toBe('pass');
    expect(rec.spfResult).toBe('fail');
    expect(summarize(r)).toMatchObject({ total: 15, passing: 15, passRate: 100 });
  });
});

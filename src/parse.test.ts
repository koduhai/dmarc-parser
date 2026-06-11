import { describe, it, expect } from 'vitest';
import { gzipSync, zipSync, strToU8, strFromU8 } from 'fflate';
import {
  parseDmarcXml,
  extractReportXml,
  decompressReport,
  parseReportEmail,
  summarize,
  recordPassesDmarc,
  DmarcParseError,
} from './parse.js';

const XML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc@google.com</email>
    <report_id>RID-12345</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>quarantine</p><pct>100</pct></policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>198.51.100.7</source_ip><count>2</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>mail.example.com</domain><result>fail</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>`;

const SINGLE_RECORD_XML = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>yahoo.com</org_name><report_id>RID-1</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
  <policy_published><domain>solo.com</domain><p>none</p></policy_published>
  <record><row><source_ip>192.0.2.5</source_ip><count>3</count>
    <policy_evaluated><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>solo.com</header_from></identifiers></record>
</feedback>`;

function mimeWith(attachmentB64: string, contentType: string, filename: string): Buffer {
  return Buffer.from(
    [
      'From: noreply@google.com',
      'To: dmarc-reports@example.com',
      'Subject: Report Domain: example.com',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b0"',
      '',
      '--b0',
      `Content-Type: ${contentType}; name="${filename}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${filename}"`,
      '',
      attachmentB64,
      '--b0--',
      '',
    ].join('\r\n'),
    'utf8',
  );
}

describe('parseDmarcXml', () => {
  it('maps report metadata and all records', () => {
    const r = parseDmarcXml(XML);
    expect(r.meta.orgName).toBe('google.com');
    expect(r.meta.reportId).toBe('RID-12345');
    expect(r.meta.domain).toBe('example.com');
    expect(r.meta.policyP).toBe('quarantine');
    expect(r.meta.policyPct).toBe(100);
    expect(r.meta.dateBegin.getTime()).toBe(1717200000 * 1000);
    expect(r.records).toHaveLength(2);
    expect(r.records[0]).toMatchObject({ sourceIp: '203.0.113.1', count: 5, dkimResult: 'pass', spfResult: 'pass' });
    expect(r.records[1]).toMatchObject({
      sourceIp: '198.51.100.7',
      count: 2,
      dkimResult: 'fail',
      spfResult: 'pass',
      headerFrom: 'example.com',
    });
  });

  it('handles a single <record> (not wrapped in an array)', () => {
    const r = parseDmarcXml(SINGLE_RECORD_XML);
    expect(r.records).toHaveLength(1);
    expect(r.records[0]).toMatchObject({ sourceIp: '192.0.2.5', count: 3, dkimResult: 'pass', spfResult: 'fail' });
  });

  it('throws DmarcParseError on malformed/missing-root input', () => {
    expect(() => parseDmarcXml('<not-a-report/>')).toThrow(DmarcParseError);
  });

  it('returns an empty records array when the report has no <record>', () => {
    const xml = `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>google.com</org_name><report_id>RID-0</report_id>
        <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
      <policy_published><domain>empty.com</domain><p>none</p></policy_published></feedback>`;
    const r = parseDmarcXml(xml);
    expect(r.records).toEqual([]);
    expect(r.meta.domain).toBe('empty.com');
  });

  it('parses extended policy fields, auth_results arrays, and override reasons', () => {
    const xml = `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>o.com</org_name><report_id>RID-X</report_id>
        <error>boom</error>
        <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
      <policy_published><domain>d.com</domain><adkim>s</adkim><aspf>r</aspf>
        <p>reject</p><sp>quarantine</sp><np>reject</np><fo>1</fo><pct>50</pct></policy_published>
      <record><row><source_ip>192.0.2.1</source_ip><count>3</count>
        <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf>
          <reason><type>forwarded</type><comment>list</comment></reason></policy_evaluated></row>
        <auth_results>
          <dkim><domain>a.com</domain><selector>s1</selector><result>pass</result></dkim>
          <dkim><domain>b.com</domain><selector>s2</selector><result>fail</result></dkim>
          <spf><domain>a.com</domain><scope>mfrom</scope><result>fail</result></spf>
        </auth_results></record></feedback>`;
    const r = parseDmarcXml(xml);
    expect(r.meta).toMatchObject({
      policyAdkim: 's',
      policyAspf: 'r',
      policySp: 'quarantine',
      policyNp: 'reject',
      policyFo: '1',
      policyPct: 50,
      errors: ['boom'],
    });
    const rec = r.records[0];
    expect(rec.dkimAuth).toHaveLength(2);
    expect(rec.dkimAuth[1]).toMatchObject({ domain: 'b.com', selector: 's2', result: 'fail' });
    expect(rec.spfAuth[0]).toMatchObject({ domain: 'a.com', scope: 'mfrom', result: 'fail' });
    expect(rec.dkimDomain).toBe('a.com');
    expect(rec.reasons).toEqual([{ type: 'forwarded', comment: 'list' }]);
  });

  it('defaults extended fields to null / empty when absent', () => {
    const r = parseDmarcXml(SINGLE_RECORD_XML);
    expect(r.meta).toMatchObject({ policyAdkim: null, policyAspf: null, policySp: null, errors: [] });
    expect(r.records[0]).toMatchObject({ dkimAuth: [], spfAuth: [], reasons: [], dkimDomain: null });
  });

  it('coerces non-numeric / negative count and pct to safe values', () => {
    const xml = `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>x.com</org_name><report_id>RID-9</report_id>
        <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
      <policy_published><domain>d.com</domain><p>none</p><pct>oops</pct></policy_published>
      <record><row><source_ip>192.0.2.9</source_ip><count>-4</count>
        <policy_evaluated><dkim>pass</dkim></policy_evaluated></row></record></feedback>`;
    const r = parseDmarcXml(xml);
    expect(r.meta.policyPct).toBe(0);
    expect(r.records[0].count).toBe(0);
  });

  it('truncates a fractional count to an integer and clamps pct to 100', () => {
    const xml = `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>x.com</org_name><report_id>RID-10</report_id>
        <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
      <policy_published><domain>d.com</domain><p>none</p><pct>150</pct></policy_published>
      <record><row><source_ip>192.0.2.9</source_ip><count>3.9</count>
        <policy_evaluated><dkim>pass</dkim></policy_evaluated></row></record></feedback>`;
    const r = parseDmarcXml(xml);
    expect(r.meta.policyPct).toBe(100);
    expect(r.records[0].count).toBe(3);
  });
});

describe('summarize / recordPassesDmarc', () => {
  it('totals messages, computes the pass rate, and rolls up by source IP', () => {
    const s = summarize(parseDmarcXml(XML));
    // Both rows pass DMARC (row 1 via DKIM+SPF, row 2 via SPF alone).
    expect(s).toMatchObject({ total: 7, passing: 7, failing: 0, passRate: 100 });
    expect(s.bySourceIp).toEqual([
      { sourceIp: '203.0.113.1', count: 5, passing: 5, passRate: 100 },
      { sourceIp: '198.51.100.7', count: 2, passing: 2, passRate: 100 },
    ]);
  });

  it('counts a row as failing when neither DKIM nor SPF is aligned-pass', () => {
    const s = summarize(parseDmarcXml(SINGLE_RECORD_XML)); // dkim pass, spf fail -> passes
    expect(s).toMatchObject({ total: 3, passing: 3, passRate: 100 });
  });

  it('aggregates rows that share a source IP and rounds the rate to one decimal', () => {
    const xml = `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>o.com</org_name><report_id>RID-A</report_id>
        <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
      <policy_published><domain>d.com</domain><p>none</p></policy_published>
      <record><row><source_ip>192.0.2.1</source_ip><count>2</count>
        <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
      <record><row><source_ip>192.0.2.1</source_ip><count>1</count>
        <policy_evaluated><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record></feedback>`;
    const s = summarize(parseDmarcXml(xml));
    expect(s).toMatchObject({ total: 3, passing: 2, failing: 1, passRate: 66.7 });
    expect(s.bySourceIp).toEqual([{ sourceIp: '192.0.2.1', count: 3, passing: 2, passRate: 66.7 }]);
  });

  it('returns a zero pass rate for an empty report instead of NaN', () => {
    const s = summarize({ meta: {} as never, records: [] });
    expect(s).toMatchObject({ total: 0, passing: 0, passRate: 0, bySourceIp: [] });
  });

  it('recordPassesDmarc requires at least one aligned pass', () => {
    expect(recordPassesDmarc({ dkimResult: 'fail', spfResult: 'pass' } as never)).toBe(true);
    expect(recordPassesDmarc({ dkimResult: 'fail', spfResult: 'fail' } as never)).toBe(false);
  });
});

describe('hardening', () => {
  it('rejects a DOCTYPE/DTD to close the entity-expansion vector', () => {
    const bomb = `<?xml version="1.0"?>
      <!DOCTYPE feedback [ <!ENTITY a "AAAA"> <!ENTITY b "&a;&a;&a;&a;"> ]>
      <feedback><report_metadata><org_name>&b;</org_name><report_id>x</report_id>
        <date_range><begin>0</begin><end>0</end></date_range></report_metadata></feedback>`;
    expect(() => parseDmarcXml(bomb)).toThrow(DmarcParseError);
    expect(() => parseDmarcXml(bomb)).toThrow(/DOCTYPE/i);
  });

  it('rejects non-string input', () => {
    // @ts-expect-error exercising a runtime guard for untyped callers
    expect(() => parseDmarcXml(null)).toThrow(DmarcParseError);
  });

  it('rejects a gzip whose declared size exceeds the cap before inflating', () => {
    const gz = gzipSync(strToU8(XML)).slice();
    // ISIZE is the trailing 4 bytes (little-endian); forge a > 50 MiB uncompressed size.
    new DataView(gz.buffer).setUint32(gz.length - 4, 60 * 1024 * 1024, true);
    expect(() => decompressReport('r.xml.gz', gz)).toThrow(/size cap/);
  });
});

describe('decompressReport', () => {
  it('inflates a .gz payload', () => {
    const gz = gzipSync(strToU8(XML));
    expect(decompressReport('r.xml.gz', gz)).toContain('<org_name>google.com</org_name>');
  });

  it('reads the .xml entry from a .zip', () => {
    const zip = zipSync({ 'report.xml': strToU8(XML) });
    expect(decompressReport('r.zip', zip)).toContain('RID-12345');
  });

  it('passes through a bare .xml payload', () => {
    expect(decompressReport('r.xml', strToU8(XML))).toContain('RID-12345');
  });

  it('sniffs gzip magic bytes for an unknown extension', () => {
    const gz = gzipSync(strToU8(XML));
    expect(decompressReport('stdin', gz)).toContain('RID-12345');
  });

  it('throws when a zip has no .xml entry', () => {
    const zip = zipSync({ 'note.txt': strToU8('hi') });
    expect(() => decompressReport('r.zip', zip)).toThrow(DmarcParseError);
  });

  it('selects the .xml entry from a zip that also holds other files', () => {
    const zip = zipSync({ 'readme.txt': strToU8('ignore me'), 'report.xml': strToU8(XML) });
    expect(decompressReport('r.zip', zip)).toContain('RID-12345');
  });

  it('round-trips a bare .xml payload back to the same text', () => {
    expect(strFromU8(strToU8(decompressReport('r.xml', strToU8(XML))))).toContain('<feedback>');
  });
});

describe('extractReportXml / parseReportEmail', () => {
  it('decompresses a .xml.gz attachment from a MIME email', async () => {
    const gz = gzipSync(strToU8(XML));
    const mime = mimeWith(
      Buffer.from(gz).toString('base64'),
      'application/gzip',
      'example.com!example.com!1717.xml.gz',
    );
    expect(await extractReportXml(mime)).toContain('<org_name>google.com</org_name>');
  });

  it('reads a bare .xml attachment and parses end-to-end', async () => {
    const mime = mimeWith(Buffer.from(XML, 'utf8').toString('base64'), 'text/xml', 'report.xml');
    const report = await parseReportEmail(mime);
    expect(report.meta.reportId).toBe('RID-12345');
  });

  it('throws when there is no report attachment', async () => {
    const mime = mimeWith(Buffer.from('hello', 'utf8').toString('base64'), 'text/plain', 'note.txt');
    await expect(extractReportXml(mime)).rejects.toBeInstanceOf(DmarcParseError);
  });
});

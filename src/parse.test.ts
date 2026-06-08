import { describe, it, expect } from 'vitest';
import { gzipSync, zipSync, strToU8 } from 'fflate';
import { parseDmarcXml, extractReportXml, decompressReport, parseReportEmail, DmarcParseError } from './parse.js';

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
    expect(r.records[1]).toMatchObject({ sourceIp: '198.51.100.7', count: 2, dkimResult: 'fail', spfResult: 'pass', headerFrom: 'example.com' });
  });

  it('handles a single <record> (not wrapped in an array)', () => {
    const r = parseDmarcXml(SINGLE_RECORD_XML);
    expect(r.records).toHaveLength(1);
    expect(r.records[0]).toMatchObject({ sourceIp: '192.0.2.5', count: 3, dkimResult: 'pass', spfResult: 'fail' });
  });

  it('throws DmarcParseError on malformed/missing-root input', () => {
    expect(() => parseDmarcXml('<not-a-report/>')).toThrow(DmarcParseError);
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
});

describe('extractReportXml / parseReportEmail', () => {
  it('decompresses a .xml.gz attachment from a MIME email', async () => {
    const gz = gzipSync(strToU8(XML));
    const mime = mimeWith(Buffer.from(gz).toString('base64'), 'application/gzip', 'example.com!example.com!1717.xml.gz');
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

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { gzipSync, zipSync, strToU8 } from 'fflate';
import { parseDmarcXml, decompressReport, summarize, DmarcParseError, type DmarcReport } from './parse.js';

// The security contract (see SECURITY.md): on *any* input, the parser either returns a
// well-formed result or throws a typed DmarcParseError. It must never throw some other error
// type, return a malformed object, or hang. These property tests assert exactly that across a
// wide space of random and adversarially-mutated inputs.

function assertWellFormed(report: DmarcReport): void {
  expect(report).toBeTypeOf('object');
  expect(report.meta).toBeTypeOf('object');
  expect(Array.isArray(report.records)).toBe(true);
  for (const rec of report.records) {
    expect(typeof rec.sourceIp).toBe('string');
    expect(Number.isFinite(rec.count)).toBe(true);
    expect(rec.count).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(rec.dkimAuth)).toBe(true);
    expect(Array.isArray(rec.spfAuth)).toBe(true);
    expect(Array.isArray(rec.reasons)).toBe(true);
  }
  // summarize() must also stay total over whatever the parser produced.
  const s = summarize(report);
  expect(Number.isFinite(s.passRate)).toBe(true);
  expect(s.passRate).toBeGreaterThanOrEqual(0);
  expect(s.total).toBe(s.passing + s.failing);
}

// An arbitrary that builds feedback-shaped XML from random (often nonsensical) field values, so
// fuzzing exercises the real parse paths rather than bouncing off the very first syntax check.
const reportLikeXml = fc
  .record({
    org: fc.string(),
    rid: fc.string(),
    domain: fc.string(),
    begin: fc.oneof(fc.integer(), fc.string()),
    end: fc.oneof(fc.integer(), fc.string()),
    p: fc.string(),
    pct: fc.oneof(fc.integer(), fc.string()),
    rows: fc.array(
      fc.record({
        ip: fc.string(),
        count: fc.oneof(fc.integer(), fc.string()),
        dkim: fc.constantFrom('pass', 'fail', 'none', ''),
        spf: fc.constantFrom('pass', 'fail', 'none', ''),
      }),
      { maxLength: 5 },
    ),
  })
  .map(
    (r) => `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>${r.org}</org_name><report_id>${r.rid}</report_id>
        <date_range><begin>${r.begin}</begin><end>${r.end}</end></date_range></report_metadata>
      <policy_published><domain>${r.domain}</domain><p>${r.p}</p><pct>${r.pct}</pct></policy_published>
      ${r.rows
        .map(
          (row) =>
            `<record><row><source_ip>${row.ip}</source_ip><count>${row.count}</count>
              <policy_evaluated><dkim>${row.dkim}</dkim><spf>${row.spf}</spf></policy_evaluated></row></record>`,
        )
        .join('')}
    </feedback>`,
  );

describe('parseDmarcXml fuzzing', () => {
  it('on arbitrary strings: returns a well-formed report or throws DmarcParseError (never else)', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        try {
          assertWellFormed(parseDmarcXml(s));
        } catch (e) {
          if (e instanceof DmarcParseError) return;
          // A vitest assertion failure inside assertWellFormed is an AssertionError; let it surface.
          if (e instanceof Error && e.constructor.name.includes('Assertion')) throw e;
          throw new Error(`unexpected ${(e as Error).constructor.name}: ${(e as Error).message}`);
        }
      }),
      { numRuns: 2000 },
    );
  });

  it('on report-shaped XML with junk field values: never produces a malformed result', () => {
    fc.assert(
      fc.property(reportLikeXml, (xml) => {
        try {
          assertWellFormed(parseDmarcXml(xml));
        } catch (e) {
          if (e instanceof DmarcParseError) return;
          if (e instanceof Error && e.constructor.name.includes('Assertion')) throw e;
          throw new Error(`unexpected ${(e as Error).constructor.name}: ${(e as Error).message}`);
        }
      }),
      { numRuns: 2000 },
    );
  });
});

describe('decompressReport fuzzing', () => {
  it('on arbitrary bytes + extension: returns a string or throws DmarcParseError (never else)', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 256 }),
        fc.constantFrom('r.xml', 'r.gz', 'r.xml.gz', 'r.zip', 'stdin', 'r.dat'),
        (bytes, name) => {
          try {
            expect(typeof decompressReport(name, bytes)).toBe('string');
          } catch (e) {
            if (e instanceof DmarcParseError) return;
            if (e instanceof Error && e.constructor.name.includes('Assertion')) throw e;
            throw new Error(`unexpected ${(e as Error).constructor.name}: ${(e as Error).message}`);
          }
        },
      ),
      { numRuns: 2000 },
    );
  });

  it('round-trips valid gzip and zip archives of arbitrary XML-ish text', () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        const payload = `<feedback>${text}</feedback>`;
        expect(decompressReport('r.xml.gz', gzipSync(strToU8(payload)))).toBe(payload);
        expect(decompressReport('r.zip', zipSync({ 'report.xml': strToU8(payload) }))).toBe(payload);
      }),
      { numRuns: 500 },
    );
  });
});

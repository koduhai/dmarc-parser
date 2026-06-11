import { simpleParser, type ParsedMail } from 'mailparser';
import { gunzipSync, unzipSync, strFromU8, type UnzipFileInfo } from 'fflate';
import { XMLParser } from 'fast-xml-parser';

/** Thrown for any malformed input: bad XML, missing root, no report attachment, oversized payload. */
export class DmarcParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DmarcParseError';
  }
}

export interface DmarcReportMeta {
  /** Reporting organization, e.g. "google.com". */
  orgName: string;
  /** The report's unique id (used for idempotent ingestion). */
  reportId: string;
  /** The domain the published policy applies to. */
  domain: string;
  /** Start of the report window. */
  dateBegin: Date;
  /** End of the report window. */
  dateEnd: Date;
  /** Published policy: "none" | "quarantine" | "reject" (or null if absent). */
  policyP: string | null;
  /** Subdomain policy: "none" | "quarantine" | "reject" (or null if absent). */
  policySp: string | null;
  /** Percentage of mail the policy was applied to (0-100), or null. */
  policyPct: number | null;
  /** DKIM alignment mode: "r" (relaxed) | "s" (strict), or null. */
  policyAdkim: string | null;
  /** SPF alignment mode: "r" (relaxed) | "s" (strict), or null. */
  policyAspf: string | null;
  /** Policy for non-existent subdomains, or null. */
  policyNp: string | null;
  /** Failure-reporting options requested by the policy, or null. */
  policyFo: string | null;
  /** Any `<error>` entries the reporter included in report_metadata. */
  errors: string[];
}

/** A single DKIM authentication result from a record's auth_results. */
export interface DkimAuthResult {
  domain: string | null;
  selector: string | null;
  result: string | null;
}

/** A single SPF authentication result from a record's auth_results. */
export interface SpfAuthResult {
  domain: string | null;
  scope: string | null;
  result: string | null;
}

/** A policy_evaluated override reason (why the applied disposition differs from policy). */
export interface DmarcReason {
  /** e.g. "forwarded", "mailing_list", "sampled_out", "trusted_forwarder", "local_policy". */
  type: string | null;
  comment: string | null;
}

export interface DmarcRecord {
  /** Sending source IP for this row. */
  sourceIp: string;
  /** Number of messages this row represents. */
  count: number;
  /** Applied disposition: "none" | "quarantine" | "reject" (or null). */
  disposition: string | null;
  /** DMARC-aligned DKIM result from policy_evaluated ("pass" | "fail"). */
  dkimResult: string | null;
  /** DMARC-aligned SPF result from policy_evaluated ("pass" | "fail"). */
  spfResult: string | null;
  /** RFC5322.From domain seen by the receiver. */
  headerFrom: string | null;
  /** Primary DKIM-authenticated domain (first auth_results entry), if any. */
  dkimDomain: string | null;
  /** Primary SPF-authenticated domain (first auth_results entry), if any. */
  spfDomain: string | null;
  /** All DKIM auth_results entries for this row (a message may carry several signatures). */
  dkimAuth: DkimAuthResult[];
  /** All SPF auth_results entries for this row. */
  spfAuth: SpfAuthResult[];
  /** policy_evaluated override reasons, if any. */
  reasons: DmarcReason[];
}

export interface DmarcReport {
  meta: DmarcReportMeta;
  records: DmarcRecord[];
}

/** Per-source-IP rollup produced by {@link summarize}. */
export interface DmarcSourceSummary {
  sourceIp: string;
  /** Total messages from this IP. */
  count: number;
  /** Messages from this IP that passed DMARC. */
  passing: number;
  /** Pass rate for this IP, 0-100 with one decimal. */
  passRate: number;
}

/** Aggregate view of a report produced by {@link summarize}. */
export interface DmarcSummary {
  /** Total messages across all records. */
  total: number;
  /** Messages that passed DMARC. */
  passing: number;
  /** Messages that failed DMARC. */
  failing: number;
  /** Overall pass rate, 0-100 with one decimal. */
  passRate: number;
  /** Per-source-IP breakdown, sorted by message count (descending). */
  bySourceIp: DmarcSourceSummary[];
}

// Cap on report payload size (compressed output and raw XML alike). Bounds what reaches the
// XML parser and limits a decompression-bomb attachment. We reject up front where the size is
// known cheaply (zip entry headers, the gzip ISIZE trailer) and re-check after inflating.
const MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024;

function capDecompressed(out: Uint8Array): Uint8Array {
  if (out.length > MAX_DECOMPRESSED_BYTES) throw new DmarcParseError('decompressed report exceeds size cap');
  return out;
}

// gzip stores the uncompressed size (mod 2^32) in its last 4 bytes. Reading it lets us reject an
// oversized payload before inflating. It is only a fast pre-check (the modulus makes it unreliable
// above 4 GiB), so capDecompressed() after inflation remains the real backstop.
function gunzipCapped(bytes: Uint8Array): Uint8Array {
  if (bytes.length >= 18) {
    const isize = new DataView(bytes.buffer, bytes.byteOffset + bytes.length - 4, 4).getUint32(0, true);
    if (isize > MAX_DECOMPRESSED_BYTES) throw new DmarcParseError('decompressed report exceeds size cap');
  }
  return capDecompressed(gunzipSync(bytes));
}

const str = (v: unknown): string | null => (v == null ? null : String(v));
const toArray = <T>(v: T | T[] | undefined): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);
const asRecord = (v: unknown): Record<string, unknown> => (v ?? {}) as Record<string, unknown>;

// Coerce to a finite, non-negative integer; anything else (NaN, "abc", -1, Infinity, 3.5) becomes
// the fallback (fractions are truncated). DMARC counts, timestamps, and percentages are
// non-negative integers; bad data should not poison them.
function toCount(v: unknown, fallback = 0): number {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : fallback;
}

/**
 * Parse aggregate report XML into a typed structure. Pure, synchronous, no I/O.
 * @throws {DmarcParseError} on invalid XML or a missing `<feedback>`/metadata.
 */
export function parseDmarcXml(xml: string): DmarcReport {
  if (typeof xml !== 'string') throw new DmarcParseError('expected XML string input');
  if (xml.length > MAX_DECOMPRESSED_BYTES) throw new DmarcParseError('XML input exceeds size cap');
  // Reject any DOCTYPE/DTD. Aggregate reports never carry one, and forbidding it closes the
  // entity-expansion ("billion laughs") vector outright: with no custom <!ENTITY> definitions only
  // the five predefined XML entities can expand, none of which amplify. (fast-xml-parser does not
  // resolve external entities, so XXE was never reachable.)
  if (/<!doctype/i.test(xml)) throw new DmarcParseError('DOCTYPE/DTD is not allowed');

  const parser = new XMLParser({ ignoreAttributes: true });
  let doc: Record<string, unknown>;
  try {
    doc = parser.parse(xml) as Record<string, unknown>;
  } catch (e) {
    throw new DmarcParseError(`invalid XML: ${(e as Error).message}`);
  }
  const feedback = doc.feedback as Record<string, unknown> | undefined;
  if (!feedback) throw new DmarcParseError('missing <feedback> root element');

  const md = (feedback.report_metadata ?? {}) as Record<string, unknown>;
  const pol = (feedback.policy_published ?? {}) as Record<string, unknown>;
  const dr = (md.date_range ?? {}) as Record<string, unknown>;

  const meta: DmarcReportMeta = {
    orgName: String(md.org_name ?? ''),
    reportId: String(md.report_id ?? ''),
    domain: String(pol.domain ?? ''),
    dateBegin: new Date(toCount(dr.begin) * 1000),
    dateEnd: new Date(toCount(dr.end) * 1000),
    policyP: str(pol.p),
    policySp: str(pol.sp),
    policyPct: pol.pct == null ? null : Math.min(100, toCount(pol.pct)),
    policyAdkim: str(pol.adkim),
    policyAspf: str(pol.aspf),
    policyNp: str(pol.np),
    policyFo: str(pol.fo),
    errors: toArray(md.error as string | string[] | undefined).map(String),
  };
  if (!meta.orgName || !meta.reportId) {
    throw new DmarcParseError('missing report_metadata org_name/report_id');
  }

  const rawRecords =
    feedback.record == null ? [] : Array.isArray(feedback.record) ? feedback.record : [feedback.record];

  const records: DmarcRecord[] = (rawRecords as Record<string, unknown>[]).map((rec) => {
    const row = asRecord(rec.row);
    const evaluated = asRecord(row.policy_evaluated);
    const identifiers = asRecord(rec.identifiers);
    const auth = asRecord(rec.auth_results);
    const dkimAuth: DkimAuthResult[] = toArray(auth.dkim)
      .map(asRecord)
      .map((d) => ({
        domain: str(d.domain),
        selector: str(d.selector),
        result: str(d.result),
      }));
    const spfAuth: SpfAuthResult[] = toArray(auth.spf)
      .map(asRecord)
      .map((s) => ({
        domain: str(s.domain),
        scope: str(s.scope),
        result: str(s.result),
      }));
    const reasons: DmarcReason[] = toArray(evaluated.reason)
      .map(asRecord)
      .map((r) => ({
        type: str(r.type),
        comment: str(r.comment),
      }));
    return {
      sourceIp: String(row.source_ip ?? ''),
      count: toCount(row.count),
      disposition: str(evaluated.disposition),
      dkimResult: str(evaluated.dkim),
      spfResult: str(evaluated.spf),
      headerFrom: str(identifiers.header_from),
      dkimDomain: dkimAuth[0]?.domain ?? null,
      spfDomain: spfAuth[0]?.domain ?? null,
      dkimAuth,
      spfAuth,
      reasons,
    };
  });

  return { meta, records };
}

/** A message passes DMARC when at least one aligned mechanism (DKIM or SPF) passes. */
export function recordPassesDmarc(rec: DmarcRecord): boolean {
  return rec.dkimResult === 'pass' || rec.spfResult === 'pass';
}

const round1 = (n: number): number => Math.round(n * 10) / 10;

/**
 * Aggregate a parsed report into message totals, an overall DMARC pass rate, and a
 * per-source-IP breakdown. Pure and synchronous; shared by the CLI summary view.
 */
export function summarize(report: DmarcReport): DmarcSummary {
  let total = 0;
  let passing = 0;
  const byIp = new Map<string, { count: number; passing: number }>();
  for (const rec of report.records) {
    const passed = recordPassesDmarc(rec);
    total += rec.count;
    if (passed) passing += rec.count;
    const agg = byIp.get(rec.sourceIp) ?? { count: 0, passing: 0 };
    agg.count += rec.count;
    if (passed) agg.passing += rec.count;
    byIp.set(rec.sourceIp, agg);
  }
  const bySourceIp: DmarcSourceSummary[] = [...byIp.entries()]
    .map(([sourceIp, a]) => ({
      sourceIp,
      count: a.count,
      passing: a.passing,
      passRate: a.count === 0 ? 0 : round1((a.passing / a.count) * 100),
    }))
    .sort((x, y) => y.count - x.count);
  return {
    total,
    passing,
    failing: total - passing,
    passRate: total === 0 ? 0 : round1((passing / total) * 100),
    bySourceIp,
  };
}

/**
 * Decompress a report payload into XML text given its filename and raw bytes.
 * Handles `.xml`, `.xml.gz`/`.gz`, and `.zip` (first `.xml` entry). For unknown
 * extensions it sniffs the gzip/zip magic bytes, else assumes raw XML.
 * @throws {DmarcParseError} on corrupt archives, a `.zip` with no `.xml` entry, or a size cap.
 */
export function decompressReport(filename: string, bytes: Uint8Array): string {
  const name = filename.toLowerCase();
  // Corrupt gzip/zip input makes the underlying codec throw its own error type; wrap everything
  // here so callers only ever see a typed DmarcParseError, never a raw fflate/decoder failure.
  try {
    if (name.endsWith('.gz')) return strFromU8(gunzipCapped(bytes));
    if (name.endsWith('.zip')) return strFromU8(capDecompressed(unzipXmlEntry(bytes)));
    if (name.endsWith('.xml')) return strFromU8(capDecompressed(bytes));
    // Unknown extension: sniff the gzip (1f 8b) or zip (PK\x03\x04) magic, else assume raw XML.
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) return strFromU8(gunzipCapped(bytes));
    if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
      return strFromU8(capDecompressed(unzipXmlEntry(bytes)));
    }
    return strFromU8(capDecompressed(bytes));
  } catch (e) {
    if (e instanceof DmarcParseError) throw e;
    throw new DmarcParseError(`could not decompress report: ${(e as Error).message}`);
  }
}

// Extract the first `.xml` entry from a zip. The filter runs against each entry's central-directory
// header *before* inflation, so checking originalSize there rejects a zip bomb without ever
// decompressing it, and skips non-xml entries entirely (their bytes are never expanded into memory).
function unzipXmlEntry(bytes: Uint8Array): Uint8Array {
  const files = unzipSync(bytes, {
    filter: (f: UnzipFileInfo) => {
      const isXml = f.name.toLowerCase().endsWith('.xml');
      if (isXml && f.originalSize > MAX_DECOMPRESSED_BYTES) {
        throw new DmarcParseError('decompressed report exceeds size cap');
      }
      return isXml;
    },
  });
  const entry = Object.values(files)[0];
  if (!entry) throw new DmarcParseError('no .xml entry inside zip');
  return entry;
}

function xmlFromAttachments(mail: ParsedMail): string {
  for (const att of mail.attachments ?? []) {
    const name = (att.filename ?? '').toLowerCase();
    const content = att.content as Buffer;
    if (name.endsWith('.gz') || name.endsWith('.zip') || name.endsWith('.xml')) {
      return decompressReport(name, new Uint8Array(content));
    }
  }
  throw new DmarcParseError('no DMARC report attachment found');
}

/**
 * Extract the aggregate XML out of a raw MIME email (the form mailbox providers send
 * RUA reports in). Decompresses the first `.gz`/`.zip`/`.xml` attachment.
 * @throws {DmarcParseError} when no report attachment is present.
 */
export async function extractReportXml(rawMime: Buffer | Uint8Array): Promise<string> {
  return xmlFromAttachments(await simpleParser(Buffer.from(rawMime)));
}

/** Convenience: extract the XML from a raw MIME email and parse it in one call. */
export async function parseReportEmail(rawMime: Buffer | Uint8Array): Promise<DmarcReport> {
  return parseDmarcXml(await extractReportXml(rawMime));
}

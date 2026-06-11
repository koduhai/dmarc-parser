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
  /** Percentage of mail the policy was applied to (0-100), or null. */
  policyPct: number | null;
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
  /** DKIM-authenticated domain from auth_results, if any. */
  dkimDomain: string | null;
  /** SPF-authenticated domain from auth_results, if any. */
  spfDomain: string | null;
}

export interface DmarcReport {
  meta: DmarcReportMeta;
  records: DmarcRecord[];
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
const firstOf = <T>(v: T | T[] | undefined): T | undefined => (Array.isArray(v) ? v[0] : v);

// Coerce to a finite, non-negative number; anything else (NaN, "abc", -1, Infinity) becomes the
// fallback. DMARC counts and percentages are non-negative integers; bad data should not poison them.
function toCount(v: unknown, fallback = 0): number {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
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
    policyPct: pol.pct == null ? null : toCount(pol.pct),
  };
  if (!meta.orgName || !meta.reportId) {
    throw new DmarcParseError('missing report_metadata org_name/report_id');
  }

  const rawRecords =
    feedback.record == null ? [] : Array.isArray(feedback.record) ? feedback.record : [feedback.record];

  const records: DmarcRecord[] = (rawRecords as Record<string, unknown>[]).map((rec) => {
    const row = (rec.row ?? {}) as Record<string, unknown>;
    const evaluated = (row.policy_evaluated ?? {}) as Record<string, unknown>;
    const identifiers = (rec.identifiers ?? {}) as Record<string, unknown>;
    const auth = (rec.auth_results ?? {}) as Record<string, unknown>;
    const dkimAuth = firstOf(auth.dkim as Record<string, unknown> | Record<string, unknown>[] | undefined);
    const spfAuth = firstOf(auth.spf as Record<string, unknown> | Record<string, unknown>[] | undefined);
    return {
      sourceIp: String(row.source_ip ?? ''),
      count: toCount(row.count),
      disposition: str(evaluated.disposition),
      dkimResult: str(evaluated.dkim),
      spfResult: str(evaluated.spf),
      headerFrom: str(identifiers.header_from),
      dkimDomain: dkimAuth ? str(dkimAuth.domain) : null,
      spfDomain: spfAuth ? str(spfAuth.domain) : null,
    };
  });

  return { meta, records };
}

/**
 * Decompress a report payload into XML text given its filename and raw bytes.
 * Handles `.xml`, `.xml.gz`/`.gz`, and `.zip` (first `.xml` entry). For unknown
 * extensions it sniffs the gzip magic bytes, else assumes raw XML.
 * @throws {DmarcParseError} when a `.zip` has no `.xml` entry or a size cap is exceeded.
 */
export function decompressReport(filename: string, bytes: Uint8Array): string {
  const name = filename.toLowerCase();
  if (name.endsWith('.gz')) {
    return strFromU8(gunzipCapped(bytes));
  }
  if (name.endsWith('.zip')) {
    return strFromU8(capDecompressed(unzipXmlEntry(bytes)));
  }
  if (name.endsWith('.xml')) {
    return strFromU8(capDecompressed(bytes));
  }
  // Unknown extension: sniff the gzip magic number (1f 8b), else assume raw XML.
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return strFromU8(gunzipCapped(bytes));
  }
  return strFromU8(capDecompressed(bytes));
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

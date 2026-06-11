export {
  parseDmarcXml,
  extractReportXml,
  parseReportEmail,
  decompressReport,
  summarize,
  recordPassesDmarc,
  DmarcParseError,
} from './parse.js';
export type {
  DmarcReport,
  DmarcReportMeta,
  DmarcRecord,
  DkimAuthResult,
  SpfAuthResult,
  DmarcReason,
  DmarcSummary,
  DmarcSourceSummary,
} from './parse.js';

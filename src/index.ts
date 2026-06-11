export {
  parseDmarcXml,
  extractReportXml,
  parseReportEmail,
  decompressReport,
  summarize,
  aggregate,
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
  DmarcAggregate,
} from './parse.js';

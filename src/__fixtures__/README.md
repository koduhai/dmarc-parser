# Report fixtures

Anonymized, representative DMARC aggregate reports modeled on the formats real
mailbox providers send. Real domains, IPs, report ids, and selectors have been
replaced with `example.com` / RFC 5737 documentation IPs; the structure (element
ordering, single-vs-array records, multiple DKIM signatures, override reasons,
extra metadata fields) mirrors what each provider emits.

If you hit a real report that does not parse, the most useful contribution is a
minimized, anonymized sample dropped in here with a matching assertion in
`fixtures.test.ts`. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

| File | Exercises |
|---|---|
| `google.xml` | Baseline single-record report, full `policy_published`, `extra_contact_info`. |
| `yahoo.xml` | Multiple `<record>` entries (array form), SPF `scope`. |
| `microsoft.xml` | Several DKIM signatures in one record, a `policy_evaluated` reason, `report_metadata` `<error>`, `fo`. |

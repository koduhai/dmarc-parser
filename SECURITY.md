# Security Policy

## Supported versions

The latest published `0.x` release receives security fixes. As this library reaches
`1.0`, this policy will be updated with a longer support window.

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public GitHub issue for a
vulnerability.

- Preferred: open a [private security advisory](https://github.com/koduhai/dmarc-parser/security/advisories/new)
  on GitHub.
- Or email **koduhai@koduhai.com** with details and reproduction steps.

We will acknowledge your report within a few business days and keep you updated on the
fix and disclosure timeline.

## Scope and threat model

This library parses **untrusted input**: DMARC aggregate reports arrive as email
attachments from third parties. It is designed with that in mind:

- **Decompression bombs** are bounded. Gzip payloads are pre-checked against the gzip
  size trailer and re-capped after inflation; zip entries are rejected by their declared
  uncompressed size *before* being decompressed, and non-`.xml` entries are never expanded.
  The decompressed-size cap is 50 MB.
- **XML entity expansion** ("billion laughs") is closed off by rejecting any input that
  contains a `DOCTYPE`/DTD. The underlying parser (`fast-xml-parser`) does not resolve
  external entities, so XXE is not reachable.
- **Malformed input** throws a typed `DmarcParseError` rather than returning partial or
  garbage data; non-numeric counts and percentages coerce to safe values.

If you find an input that bypasses any of these protections (excessive memory or CPU,
a crash that is not a `DmarcParseError`, or incorrect parsing of a crafted report),
that is in scope and we want to hear about it.

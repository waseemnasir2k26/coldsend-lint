# Changelog

All notable changes to this project are documented in this file.

## [2026.10] - 2026-10-12

- coldsend-lint is a Python CLI that lints a cold-email campaign on sending-domain deliverability (MX, SPF, DKIM, DMARC, PTR, DNSBL) and copy legality for us, eu, uk, es and ca rulesets. MIT licensed, public.
- Reviewed October 2026: tree re-checked (coldsend_lint package, rules/ YAML, examples, pytest suite, LICENSE); the README's two external links (skynetjoe.com, Calendly) returned HTTP 200.
- Known gaps, per the README's own Limitations: static analysis only and not legal advice; cannot verify unsubscribe links work; DNSBL results are point-in-time; SPF lookup counting does not expand nested includes; copy rules are English-first regex heuristics.
- No CI workflow in the repo. pyproject.toml version (0.1.0) deliberately left alone; this release is a repo tag only.
- Release housekeeping only: Status line, changelog and hire section links updated. No rules or code changes.

## [2026.09] - 2026-09-16

- Maintenance review of `coldsend-lint` — a Python CLI that lints a cold-email campaign on two axes before sending: sending-domain deliverability, and whether the copy meets the rules of the jurisdictions the recipients are actually in.
- Status: deliverability checks cover MX, SPF, DKIM (18 probed selectors), DMARC, PTR, five DNSBL zones and copy-hygiene heuristics; legal rulesets ship as plain YAML in `rules/` for `us` (CAN-SPAM), `eu` (GDPR + ePrivacy), `uk` (PECR + UK GDPR), `es` (LSSI-CE + LOPDGDD) and `ca` (CASL), with a routing banner that warns when a consent-based regime is in scope. Every finding carries an id, severity, jurisdiction, fix and citation; exit codes drive CI use. Example good/bad messages live in `examples/`, and there is a pytest suite covering the CLI, DNS checks, copy checks, the resolver and the rule loader. MIT licensed.
- Reviewed September 2026: documentation refreshed, CHANGELOG added and the project versioned as v2026.09.
- Known gaps, as the README's own Limitations and "Not legal advice" sections state: this is static analysis only and is not legal advice or a safe harbour; it cannot verify that an unsubscribe link actually works; DNSBL results are point-in-time and say nothing about Google/Microsoft/Yahoo reputation; DKIM absence cannot be proven; SPF lookup counting does not expand nested `include:` chains; copy rules are regex heuristics and English-first; and jurisdiction routing is per-run, not per-recipient. There is also no CI workflow in the repo.
- The `pyproject.toml` version (0.1.0) was deliberately left untouched: this release tags the repo as v2026.09 and does not cut a new package version.
- No rules, code or packaging changes were made in this release — documentation only.

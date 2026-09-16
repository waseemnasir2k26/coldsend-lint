# coldsend-lint

One CLI that checks a cold-email campaign on both axes before you send it: whether your sending domain is set up to be delivered, and whether your copy is legal for the countries your recipients are actually in.

## Status

Last reviewed: September 2026 · release v2026.09


```text
$ coldsend-lint all tinbridge.example examples/bad-email.txt -j us,eu,ca --quiet

coldsend-lint  tinbridge.example + examples/bad-email.txt
jurisdictions: US, EU, CA
------------------------------------------------------------------------------

JURISDICTION ROUTING
  CA: CASL (Canada) - regime: consent - recipients in: CA
  EU: GDPR + ePrivacy Directive (European Economic Area) - regime: consent -
  recipients in: AT, BE, BG, HR, CY, CZ, DK, EE (+22 more)
  US: CAN-SPAM Act (United States) - regime: opt-out - recipients in: US
  WARNING: CA, EU are consent-based regimes. CAN-SPAM's opt-out model is NOT
  sufficient for those recipients: under GDPR/ePrivacy, PECR, LSSI-CE and
  CASL you generally need a lawful basis or consent BEFORE you send, and the
  burden of proving it is on you. A message that passes the US rules can
  still be unlawful in the EU, the UK, Spain or Canada.

DELIVERABILITY
  ERROR  DNS-DKIM-NOT-FOUND  No DKIM key found
        None of the 18 probed selectors returned a key at
        <selector>._domainkey.tinbridge.example. DKIM selectors cannot be
        enumerated from DNS, so this means 'not found', not proof of absence.
        fix: Enable DKIM signing at your sending provider and publish the
        selector record. Re-run with --dkim-selector <name> for a custom one.
        cite: RFC 6376 (DKIM)

  ERROR  COPY-MERGE-TAG-UNMERGED  Unmerged personalisation token in the copy
        > {{first_name}}
        > {{unsubscribe_url}}
        fix: Fix the field mapping, or add a fallback for every token used.
        cite: coldsend-lint copy hygiene

   WARN  DNS-SPF-NEUTRAL-ALL  SPF record ends in ?all (neutral)
        > v=spf1 include:_spf.example.net ?all
        fix: Move to ~all, then -all once you have inventoried senders.
        cite: RFC 7208 sec. 5.1

   WARN  COPY-SPAM-TRIGGER-PHRASES  Several spam-trigger phrases in one message
        > Act now  > limited time  > risk-free  > Click here  > Dear Friend
        fix: Rewrite in plain, specific language.
        cite: coldsend-lint copy hygiene

LEGAL / COPY COMPLIANCE
  ERROR  CA-CONSENT-NOT-EVIDENCED  [CA] No express or implied consent basis stated
        Nothing in this copy points at express consent, an existing business
        relationship, or a conspicuously published address relevant to the
        recipient's role.
        fix: Say which basis you are relying on, or send only to recipients
        whose express consent you have logged.
        cite: CASL S.C. 2010 c. 23, s. 6(1) and s. 10(9)

  ERROR  EU-DATA-SOURCE-NOT-STATED  [EU] The message does not say where the address came from
        fix: Name the source explicitly, e.g. "I found your address on your
        company's public contact page".
        cite: GDPR Art. 14(2)(f)

  ERROR  US-DECEPTIVE-THREAD-PREFIX  [US] Fake Re:/Fwd: prefix on a first-contact subject
        > Subject: Re: your Q3 shipping spend
        > no In-Reply-To or References header
        fix: Drop the prefix and write an honest subject.
        cite: 15 U.S.C. sec. 7704(a)(2); FTC Act sec. 5

  ERROR  US-POSTAL-ADDRESS-MISSING  [US] No physical postal address
        cite: 15 U.S.C. sec. 7704(a)(5)(A)(iii)

  ... 13 more findings

------------------------------------------------------------------------------
13 error(s)  8 warning(s)  2 info
exit code: 2
```

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![tests](https://img.shields.io/badge/tests-120%20passing-brightgreen)
![offline tests](https://img.shields.io/badge/tests-zero%20network-informational)
![license](https://img.shields.io/badge/license-MIT-green)

## Quick start

```bash
pip install coldsend-lint            # or: pip install -e . from a checkout

coldsend-lint dns  example.com --ip 203.0.113.10
coldsend-lint copy message.txt --jurisdiction us,eu,uk
coldsend-lint all  example.com message.txt --jurisdiction all --json
```

That is the whole tool. `--jurisdiction` takes `us`, `eu`, `uk`, `es`, `ca` or `all`; `--ip` adds reverse-DNS and blacklist checks; `--json` and `--sarif` give you machine-readable output.

## What it checks

### Deliverability (the sending domain)

| Check        | ID prefix     | Fails on                                                                             |
| ------------ | ------------- | ------------------------------------------------------------------------------------ |
| MX           | `DNS-MX-*`    | no MX record, so replies have nowhere to land                                        |
| SPF          | `DNS-SPF-*`   | missing, duplicated, `+all`, `?all`, no `all`, over the 10-lookup limit              |
| DKIM         | `DNS-DKIM-*`  | no key on any of 18 probed selectors; revoked or under-sized keys                    |
| DMARC        | `DNS-DMARC-*` | missing, invalid `p=`, `p=none`, no `rua=`                                           |
| PTR          | `DNS-PTR-*`   | no reverse DNS, or a PTR that does not forward-confirm                               |
| Blacklists   | `DNS-BL-*`    | listed on Spamhaus ZEN, SpamCop, Barracuda, SORBS, PSBL                              |
| Copy hygiene | `COPY-*`      | unmerged merge tags, spam-trigger clusters, shouting, link density, image-heavy mail |

DKIM selectors cannot be enumerated from DNS, so the DKIM check probes a list of common selectors and reports "not found", never "absent". Add yours with `--dkim-selector`.

The `COPY-*` rules are deliverability, not law. They are reported under their own heading and live in `rules/global-copy.yaml`.

### Legal rules by jurisdiction

| Code | Regime      | Ruleset                      | Rules                                                                                                                                    |
| ---- | ----------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `us` | opt-out     | CAN-SPAM Act                 | opt-out present and actionable, physical postal address, deceptive `Re:`/`Fwd:` prefix, sender identity, advertisement disclosure        |
| `eu` | consent     | GDPR + ePrivacy              | lawful basis stated, data source stated (Art. 14), privacy notice link, right to object, controller identity, opt-out                    |
| `uk` | soft opt-in | PECR + UK GDPR               | opt-out, identity not concealed, valid contact address, data source, sole-trader advisory                                                |
| `es` | consent     | LSSI-CE Art. 20-21 + LOPDGDD | prior authorisation or prior relationship, "publicidad" label, advertiser identity, free revocation channel, data source, postal address |
| `ca` | consent     | CASL                         | express or implied consent basis, sender identified, mailing address valid 60 days, unsubscribe present and readily performed            |

Every finding carries an `id`, a `severity`, a `jurisdiction`, what is wrong, how to fix it and a citation string. Rules are plain YAML in `rules/`, one file per jurisdiction — copy one to add your own regime (there is a test that does exactly that).

## Jurisdiction matrix

Route by where the **recipient** is, not where you are.

| Recipient country                                                                                                                          | Regime that applies                         | Consent needed before you send?                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| United States                                                                                                                              | CAN-SPAM (`us`)                             | No — opt-out model, but identity + postal address + honest subject are mandatory                                                  |
| EEA member states (AT, BE, BG, HR, CY, CZ, DK, EE, FI, FR, DE, GR, HU, IE, IT, LV, LT, LU, MT, NL, PL, PT, RO, SK, SI, ES, SE, IS, LI, NO) | GDPR + ePrivacy (`eu`)                      | Yes for natural persons; some member states allow B2B role addresses on legitimate interests, and you still owe an Art. 14 notice |
| Spain                                                                                                                                      | GDPR + ePrivacy **and** LSSI-CE (`eu`,`es`) | Yes — Art. 21 LSSI-CE is stricter than the GDPR baseline                                                                          |
| United Kingdom                                                                                                                             | PECR + UK GDPR (`uk`)                       | Yes for individuals; limited companies and LLPs are exempt, sole traders and unincorporated partnerships are **not**              |
| Canada                                                                                                                                     | CASL (`ca`)                                 | Yes — express or implied, provable, before the send                                                                               |

> **CAN-SPAM is not enough.** The US opt-out model is the most permissive regime on this list, and passing the `us` ruleset carries no weight anywhere else. If a single recipient sits in the EEA, the UK, Spain or Canada, that recipient's rules apply to that message: you generally need a lawful basis or consent **before** you send, and the burden of proving it is yours. coldsend-lint prints this warning in the routing banner whenever a consent-based jurisdiction is in scope.

## CI usage

Exit codes are the whole integration story.

| Code | Meaning            |
| ---- | ------------------ |
| `0`  | clean              |
| `1`  | warnings only      |
| `2`  | at least one error |

```yaml
# .github/workflows/outbound.yml
name: outbound-lint
on: [pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install coldsend-lint
      # fail the PR on errors, tolerate warnings
      - run: coldsend-lint copy campaigns/q3-outreach.txt -j us,eu,uk,ca
      # full run including DNS, uploaded as a code-scanning report
      - run: coldsend-lint all example.com campaigns/q3-outreach.txt -j all --sarif > coldsend.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: coldsend.sarif
```

To treat warnings as failures, use `[ $? -eq 0 ]`; to tolerate them, use `[ $? -le 1 ]`.

## Not legal advice

**coldsend-lint is an automated checklist, not legal advice.** It is built from public summaries of the named statutes and it cannot read your contracts, your consent records, your suppression lists or your recipient list. Laws change, regulators differ in how they enforce them, and the rules here are simplified on purpose so they can run in a terminal. A clean run is not a defence and creates no safe harbour. Before you run outbound at scale, have a qualified lawyer in each relevant jurisdiction review your programme.

The same disclaimer is printed at the bottom of every report and in `coldsend-lint --help`.

## Limitations

Worth knowing before you trust a green run:

- **Static analysis only.** The linter reads your message and your DNS. It does not send anything, does not open a SMTP session, and does not render your HTML in a real client.
- **It cannot verify that your unsubscribe link works.** It checks that an opt-out is present and that something actionable is attached to it. Whether the link resolves, whether the page loads, and whether you actually honour the request within the statutory window are all outside its reach.
- **Blacklist checks are point-in-time.** A clean DNSBL result means those zones did not list your IP at that second. It says nothing about the reputation systems at Google, Microsoft or Yahoo, which publish no DNSBL at all. Public DNSBL mirrors also refuse queries from large shared resolvers, which is reported as `DNS-BL-UNREACHABLE`, not as clean.
- **DKIM absence cannot be proven.** Selectors are not enumerable; the tool probes 18 common ones.
- **SPF lookup counting is static.** Nested `include:` chains are not expanded, so the real lookup count can be higher than reported.
- **Copy rules are regex and heuristics.** The postal-address check recognises common street, P.O. box and postcode shapes, and the identity check looks for a sign-off plus a company or website. Unusual formatting can produce a false pass; the fix is to add a rule, not to trust the silence.
- **English-first.** The rulesets carry some Spanish, German and French opt-out vocabulary, but a campaign written entirely in another language needs its own patterns adding to `rules/`.
- **Jurisdiction routing is per-run, not per-recipient.** The tool lints one message against the jurisdictions you name. Segment your list yourself.

## Contributing

Rules are data. To add a jurisdiction, drop a YAML file in `rules/` with a `jurisdiction` code, a `regime`, an `applies_to` list of ISO-3166 alpha-2 recipient countries, and your rules — each with an `id`, `severity`, `title`, `what`, `fix`, `citation` and a `check`. Generic `require_any` / `forbid_any` checks cover most rules from data alone; the builtins in `coldsend_lint/copy_checks.py` handle the ones that need real logic and take their vocabulary from YAML params, so a non-English ruleset supplies its own words.

```bash
pip install -e ".[dev]"
python -m pytest -q          # 120 tests, no network required
```

Two rules the test suite enforces: every shipped rule must have a test that makes it fire, and no test may touch the network. All DNS work goes through the `Resolver` protocol in `coldsend_lint/resolver.py`, and the suite injects `FakeResolver`. Citations should point at a statute or an RFC, and please keep the honest voice — this tool's value is that it does not overstate what it knows.

---

Built by SkynetLabs (Waseem Nasir) — we build compliant outbound systems for agencies. https://skynetjoe.com · https://calendly.com/skynetlabs/schedule-a-free-consultation

## License

MIT. See [LICENSE](LICENSE).

"""Every DNS check, offline, against an injected FakeResolver."""

from __future__ import annotations

from conftest import healthy_dns

from coldsend_lint.dns_checks import (
    check_dkim,
    check_dmarc,
    check_dnsbl,
    check_mx,
    check_ptr,
    check_spf,
    run_dns_checks,
)
from coldsend_lint.findings import exit_code
from coldsend_lint.resolver import FakeResolver

DOMAIN = "tinbridge.example"
IP = "203.0.113.10"


def ids(findings):
    return [f.id for f in findings]


# --------------------------------------------------------------------- MX


def test_mx_present():
    r = FakeResolver({(DOMAIN, "MX"): ["10 mail.tinbridge.example"]})
    assert ids(check_mx(r, DOMAIN)) == ["DNS-MX-OK"]


def test_mx_missing_is_an_error():
    r = FakeResolver({(DOMAIN, "TXT"): ["v=spf1 -all"]})
    findings = check_mx(r, DOMAIN)
    assert ids(findings) == ["DNS-MX-MISSING"]
    assert findings[0].severity == "error"


def test_mx_timeout_is_a_warning_not_an_error():
    r = FakeResolver({}, timeouts={DOMAIN})
    findings = check_mx(r, DOMAIN)
    assert ids(findings) == ["DNS-MX-TIMEOUT"]
    assert findings[0].severity == "warn"


# -------------------------------------------------------------------- SPF


def test_spf_ok():
    r = FakeResolver({(DOMAIN, "TXT"): ["v=spf1 include:_spf.example.net -all"]})
    assert ids(check_spf(r, DOMAIN)) == ["DNS-SPF-OK"]


def test_spf_missing():
    r = FakeResolver({(DOMAIN, "TXT"): ["google-site-verification=abc"]})
    findings = check_spf(r, DOMAIN)
    assert ids(findings) == ["DNS-SPF-MISSING"]
    assert findings[0].severity == "error"


def test_spf_plus_all_is_an_error():
    r = FakeResolver({(DOMAIN, "TXT"): ["v=spf1 +all"]})
    assert "DNS-SPF-PLUS-ALL" in ids(check_spf(r, DOMAIN))


def test_spf_neutral_all_is_a_warning():
    r = FakeResolver({(DOMAIN, "TXT"): ["v=spf1 include:a.example ?all"]})
    findings = check_spf(r, DOMAIN)
    assert ids(findings) == ["DNS-SPF-NEUTRAL-ALL"]
    assert findings[0].severity == "warn"


def test_spf_missing_all_mechanism():
    r = FakeResolver({(DOMAIN, "TXT"): ["v=spf1 include:a.example"]})
    assert "DNS-SPF-NO-ALL" in ids(check_spf(r, DOMAIN))


def test_spf_multiple_records():
    r = FakeResolver({(DOMAIN, "TXT"): ["v=spf1 -all", "v=spf1 include:b.example ~all"]})
    assert "DNS-SPF-MULTIPLE" in ids(check_spf(r, DOMAIN))


def test_spf_lookup_limit_exceeded():
    record = "v=spf1 " + " ".join(f"include:s{i}.example" for i in range(11)) + " -all"
    r = FakeResolver({(DOMAIN, "TXT"): [record]})
    findings = check_spf(r, DOMAIN)
    assert "DNS-SPF-TOO-MANY-LOOKUPS" in ids(findings)
    assert exit_code(findings) == 2


def test_spf_lookup_limit_near():
    record = "v=spf1 mx a " + " ".join(f"include:s{i}.example" for i in range(7)) + " -all"
    r = FakeResolver({(DOMAIN, "TXT"): [record]})
    assert "DNS-SPF-LOOKUPS-NEAR-LIMIT" in ids(check_spf(r, DOMAIN))


# ------------------------------------------------------------------- DKIM


def test_dkim_found_on_a_probed_selector():
    r = FakeResolver(
        {(f"google._domainkey.{DOMAIN}", "TXT"): ["v=DKIM1; k=rsa; p=" + "A" * 392]}
    )
    findings = check_dkim(r, DOMAIN)
    assert ids(findings) == ["DNS-DKIM-OK"]
    assert "google" in findings[0].evidence[0]


def test_dkim_selector_discovery_probes_every_selector():
    r = FakeResolver({})
    check_dkim(r, DOMAIN, selectors=("default", "google", "k1"))
    assert [q[0] for q in r.queries] == [
        f"default._domainkey.{DOMAIN}",
        f"google._domainkey.{DOMAIN}",
        f"k1._domainkey.{DOMAIN}",
    ]


def test_dkim_not_found_is_an_error():
    r = FakeResolver({})
    findings = check_dkim(r, DOMAIN, selectors=("default",))
    assert ids(findings) == ["DNS-DKIM-NOT-FOUND"]
    assert findings[0].severity == "error"


def test_dkim_revoked_key_is_flagged():
    r = FakeResolver({(f"default._domainkey.{DOMAIN}", "TXT"): ["v=DKIM1; k=rsa; p="]})
    findings = check_dkim(r, DOMAIN, selectors=("default",))
    assert ids(findings) == ["DNS-DKIM-OK", "DNS-DKIM-WEAK-KEY"]


# ------------------------------------------------------------------ DMARC


def test_dmarc_ok():
    r = FakeResolver(
        {(f"_dmarc.{DOMAIN}", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@x.example"]}
    )
    assert ids(check_dmarc(r, DOMAIN)) == ["DNS-DMARC-OK"]


def test_dmarc_missing_is_an_error():
    r = FakeResolver({})
    findings = check_dmarc(r, DOMAIN)
    assert ids(findings) == ["DNS-DMARC-MISSING"]
    assert findings[0].severity == "error"


def test_dmarc_p_none_warns_and_no_rua_warns():
    r = FakeResolver({(f"_dmarc.{DOMAIN}", "TXT"): ["v=DMARC1; p=none"]})
    findings = check_dmarc(r, DOMAIN)
    assert ids(findings) == ["DNS-DMARC-POLICY-NONE", "DNS-DMARC-NO-RUA"]
    assert exit_code(findings) == 1


def test_dmarc_invalid_policy():
    r = FakeResolver({(f"_dmarc.{DOMAIN}", "TXT"): ["v=DMARC1; rua=mailto:d@x.example"]})
    assert "DNS-DMARC-POLICY-INVALID" in ids(check_dmarc(r, DOMAIN))


# -------------------------------------------------------------------- PTR


def test_ptr_forward_confirmed():
    r = FakeResolver(healthy_dns())
    assert ids(check_ptr(r, IP)) == ["DNS-PTR-OK"]


def test_ptr_missing():
    r = FakeResolver({})
    findings = check_ptr(r, IP)
    assert ids(findings) == ["DNS-PTR-MISSING"]
    assert findings[0].severity == "error"


def test_ptr_without_forward_confirmation_warns():
    records = healthy_dns()
    records[("mail.tinbridge.example", "A")] = ["198.51.100.5"]
    findings = check_ptr(FakeResolver(records), IP)
    assert ids(findings) == ["DNS-PTR-NO-FORWARD-CONFIRM"]
    assert findings[0].severity == "warn"


def test_ptr_rejects_invalid_ip():
    assert ids(check_ptr(FakeResolver({}), "999.1.1.1")) == ["DNS-PTR-BAD-IP"]


# ------------------------------------------------------------------ DNSBL


def test_dnsbl_clean():
    findings = check_dnsbl(FakeResolver({}), IP, zones=("zen.spamhaus.org",))
    assert ids(findings) == ["DNS-BL-CLEAN"]


def test_dnsbl_listed_is_an_error():
    r = FakeResolver({("10.113.0.203.zen.spamhaus.org", "A"): ["127.0.0.4"]})
    findings = check_dnsbl(r, IP, zones=("zen.spamhaus.org", "bl.spamcop.net"))
    assert ids(findings) == ["DNS-BL-LISTED"]
    assert findings[0].severity == "error"
    assert "zen.spamhaus.org -> 127.0.0.4" in findings[0].evidence


def test_dnsbl_unreachable_zone_warns():
    r = FakeResolver({}, timeouts={"10.113.0.203.bl.spamcop.net"})
    findings = check_dnsbl(r, IP, zones=("bl.spamcop.net",))
    assert ids(findings) == ["DNS-BL-CLEAN", "DNS-BL-UNREACHABLE"]


# ------------------------------------------------------------- full sweep


def test_healthy_domain_is_clean():
    r = FakeResolver(healthy_dns())
    findings = run_dns_checks(r, DOMAIN, ip=IP)
    assert exit_code(findings) == 0
    assert all(f.severity == "info" for f in findings)


def test_empty_zone_produces_errors_on_every_axis():
    findings = run_dns_checks(FakeResolver({}), DOMAIN, ip=IP)
    got = set(ids(findings))
    assert {
        "DNS-MX-MISSING",
        "DNS-SPF-MISSING",
        "DNS-DKIM-NOT-FOUND",
        "DNS-DMARC-MISSING",
        "DNS-PTR-MISSING",
    } <= got
    assert exit_code(findings) == 2


def test_no_ip_skips_ptr_and_dnsbl():
    r = FakeResolver(healthy_dns())
    findings = run_dns_checks(r, DOMAIN)
    assert "DNS-PTR-SKIPPED" in ids(findings)
    assert not any(q[1] == "PTR" for q in r.queries)
    assert exit_code(findings) == 0


def test_skip_dnsbl_flag():
    r = FakeResolver(healthy_dns())
    run_dns_checks(r, DOMAIN, ip=IP, skip_dnsbl=True)
    assert not any("spamhaus" in q[0] for q in r.queries)


def test_domain_is_normalised_before_lookup():
    r = FakeResolver(healthy_dns())
    run_dns_checks(r, "  TinBridge.Example.  ")
    assert (DOMAIN, "MX") in [(q[0], q[1]) for q in r.queries]

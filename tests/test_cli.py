"""CLI behaviour, exit codes and output formats. No network: the resolver is injected."""

from __future__ import annotations

import io
import json

import pytest
from conftest import healthy_dns

from coldsend_lint.cli import run
from coldsend_lint.report import DISCLAIMER
from coldsend_lint.resolver import FakeResolver

DOMAIN = "tinbridge.example"
IP = "203.0.113.10"


def healthy_factory(_args):
    return FakeResolver(healthy_dns())


def empty_factory(_args):
    return FakeResolver({})


def call(argv, factory=empty_factory):
    out = io.StringIO()
    code = run(argv, resolver_factory=factory, stream=out)
    return code, out.getvalue()


# ------------------------------------------------------------- exit codes


def test_exit_0_when_everything_is_clean(good_email):
    code, text = call(
        ["all", DOMAIN, str(good_email), "--ip", IP, "-j", "all"], healthy_factory
    )
    assert code == 0
    assert "0 error(s)  0 warning(s)" in text


def test_exit_2_on_errors(bad_email):
    code, _ = call(["copy", str(bad_email), "-j", "all"])
    assert code == 2


def test_exit_1_on_warnings_only():
    code, text = call(["dns", DOMAIN], healthy_dmarc_none_factory)
    assert code == 1
    assert "exit code: 1" in text


def healthy_dmarc_none_factory(_args):
    records = healthy_dns()
    records[(f"_dmarc.{DOMAIN}", "TXT")] = [f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}"]
    return FakeResolver(records)


def test_dns_errors_exit_2():
    code, text = call(["dns", DOMAIN])
    assert code == 2
    assert "DNS-SPF-MISSING" in text


# ----------------------------------------------------------- output modes


def test_json_output_is_machine_readable(bad_email):
    code, text = call(["copy", str(bad_email), "-j", "us,eu", "--json"])
    payload = json.loads(text)
    assert code == 2 == payload["summary"]["exit_code"]
    assert payload["jurisdictions"] == ["us", "eu"]
    assert payload["disclaimer"] == DISCLAIMER
    first = payload["findings"][0]
    assert set(first) >= {
        "id", "severity", "category", "jurisdiction", "title", "detail", "fix",
        "citation", "evidence",
    }


def test_sarif_output_is_valid_sarif(bad_email):
    _, text = call(["copy", str(bad_email), "-j", "us", "--sarif"])
    doc = json.loads(text)
    assert doc["version"] == "2.1.0"
    run_ = doc["runs"][0]
    assert run_["tool"]["driver"]["name"] == "coldsend-lint"
    assert run_["results"]
    assert {r["level"] for r in run_["results"]} <= {"error", "warning", "note"}
    rule_ids = {r["id"] for r in run_["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run_["results"]} <= rule_ids


def test_quiet_hides_info_findings_but_not_the_count(good_email):
    _, loud = call(["copy", str(good_email), "-j", "uk"])
    _, quiet = call(["copy", str(good_email), "-j", "uk", "--quiet"])
    assert "UK-SOLE-TRADER-RISK" in loud
    assert "UK-SOLE-TRADER-RISK" not in quiet
    assert "1 info" in quiet


def test_disclaimer_is_in_the_terminal_report(good_email):
    _, text = call(["copy", str(good_email), "-j", "us"])
    assert "NOT LEGAL ADVICE" in text


def test_disclaimer_is_in_help(capsys):
    with pytest.raises(SystemExit):
        run(["--help"])
    assert "NOT LEGAL ADVICE" in capsys.readouterr().out


# ------------------------------------------------------ jurisdiction routing


def test_routing_banner_warns_that_can_spam_is_not_enough(good_email):
    # The terminal report word-wraps, so assert on the unwrapped JSON note.
    _, raw = call(["copy", str(good_email), "-j", "us,eu,ca", "--json"])
    notes = " ".join(json.loads(raw)["regime_notes"])
    assert "CAN-SPAM's opt-out model is NOT sufficient" in notes
    assert "CA, EU are consent-based regimes" in notes

    _, text = call(["copy", str(good_email), "-j", "us,eu,ca"])
    assert "JURISDICTION ROUTING" in text
    assert "consent-based regimes" in text


def test_us_only_run_tells_you_the_other_regimes_are_stricter(good_email):
    _, raw = call(["copy", str(good_email), "-j", "us", "--json"])
    notes = " ".join(json.loads(raw)["regime_notes"])
    assert "Only opt-out jurisdictions selected" in notes
    assert "CAN-SPAM compliance does not carry over" in notes


def test_only_selected_jurisdictions_produce_findings(bad_email):
    _, text = call(["copy", str(bad_email), "-j", "us", "--json"])
    payload = json.loads(text)
    juris = {f["jurisdiction"] for f in payload["findings"]}
    assert juris <= {"US", "-"}


def test_unknown_jurisdiction_exits_2(bad_email, capsys):
    code, _ = call(["copy", str(bad_email), "-j", "atlantis"])
    assert code == 2
    assert "unknown jurisdiction" in capsys.readouterr().err


def test_missing_message_file_exits_2(capsys):
    code, _ = call(["copy", "does-not-exist.txt"])
    assert code == 2
    assert "not found" in capsys.readouterr().err


# ------------------------------------------------------------ dns plumbing


def test_custom_dkim_selector_is_probed_first():
    captured = {}

    def factory(_args):
        r = FakeResolver({})
        captured["r"] = r
        return r

    call(["dns", DOMAIN, "--dkim-selector", "acme7"], factory)
    dkim_queries = [q[0] for q in captured["r"].queries if "_domainkey" in q[0]]
    assert dkim_queries[0] == f"acme7._domainkey.{DOMAIN}"


def test_no_dnsbl_flag_skips_blacklist_queries():
    captured = {}

    def factory(_args):
        r = FakeResolver(healthy_dns())
        captured["r"] = r
        return r

    call(["dns", DOMAIN, "--ip", IP, "--no-dnsbl"], factory)
    assert not any("spamhaus" in q[0] for q in captured["r"].queries)


def test_all_command_runs_both_axes(good_email):
    _, text = call(["all", DOMAIN, str(good_email), "-j", "eu"], healthy_factory)
    assert "DELIVERABILITY" in text
    assert "JURISDICTION ROUTING" in text
    assert DOMAIN in text

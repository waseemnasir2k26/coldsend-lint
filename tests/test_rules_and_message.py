"""Ruleset loading, jurisdiction routing, and message parsing."""

from __future__ import annotations

import pytest
from conftest import RULES_DIR

from coldsend_lint.message import parse_message
from coldsend_lint.rules import (
    RulesetError,
    consent_jurisdictions,
    country_matrix,
    load_rulesets,
    parse_ruleset,
    select,
    selectable,
)


def test_all_five_jurisdictions_plus_the_global_set_load():
    rulesets = load_rulesets(RULES_DIR)
    assert set(rulesets) == {"us", "eu", "uk", "es", "ca", "global"}
    assert selectable(rulesets) == ["ca", "es", "eu", "uk", "us"]


def test_every_rule_has_a_citation_and_a_fix():
    for rs in load_rulesets(RULES_DIR).values():
        for rule in rs.rules:
            assert rule.citation.strip()
            assert rule.fix.strip()
            assert rule.what.strip()


def test_rule_ids_are_globally_unique():
    ids = [r.id for rs in load_rulesets(RULES_DIR).values() for r in rs.rules]
    assert len(ids) == len(set(ids))


def test_global_copy_rules_are_deliverability_not_legal():
    rulesets = load_rulesets(RULES_DIR)
    assert all(r.category == "deliverability" for r in rulesets["global"].rules)
    assert all(
        r.category == "legal"
        for code, rs in rulesets.items()
        if code != "global"
        for r in rs.rules
    )


def test_selecting_one_jurisdiction_still_loads_the_always_set():
    rulesets = load_rulesets(RULES_DIR)
    chosen, unknown = select(rulesets, ["us"])
    assert unknown == []
    assert {rs.jurisdiction for rs in chosen} == {"us", "global"}


def test_all_selects_every_selectable_jurisdiction():
    rulesets = load_rulesets(RULES_DIR)
    chosen, _ = select(rulesets, ["all"])
    assert {rs.jurisdiction for rs in chosen} == set(rulesets)


def test_unknown_jurisdiction_is_reported():
    rulesets = load_rulesets(RULES_DIR)
    chosen, unknown = select(rulesets, ["us", "atlantis"])
    assert unknown == ["atlantis"]
    assert {rs.jurisdiction for rs in chosen} == {"us", "global"}


def test_global_cannot_be_requested_directly():
    rulesets = load_rulesets(RULES_DIR)
    _, unknown = select(rulesets, ["global"])
    assert unknown == ["global"]


def test_country_matrix_routes_recipients_to_regimes():
    matrix = country_matrix(load_rulesets(RULES_DIR))
    assert matrix["US"] == ["us"]
    assert matrix["DE"] == ["eu"]
    assert matrix["ES"] == ["es", "eu"]  # Spain is EEA AND has its own LSSI-CE layer
    assert matrix["GB"] == ["uk"]
    assert matrix["CA"] == ["ca"]


def test_consent_jurisdictions_excludes_can_spam():
    rulesets = load_rulesets(RULES_DIR)
    chosen, _ = select(rulesets, ["all"])
    codes = {rs.jurisdiction for rs in consent_jurisdictions(chosen)}
    assert codes == {"eu", "uk", "es", "ca"}
    assert "us" not in codes


def test_a_user_can_add_their_own_ruleset(tmp_path):
    (tmp_path / "za.yaml").write_text(
        "jurisdiction: za\n"
        "name: POPIA (South Africa)\n"
        "regime: consent\n"
        "applies_to: [ZA]\n"
        "rules:\n"
        "  - id: ZA-TEST\n"
        "    severity: warn\n"
        "    title: t\n"
        "    what: w\n"
        "    fix: f\n"
        "    citation: c\n"
        "    check:\n"
        "      type: require_any\n"
        "      patterns: ['never going to match this']\n",
        encoding="utf-8",
    )
    rulesets = load_rulesets(tmp_path)
    assert selectable(rulesets) == ["za"]


def test_malformed_ruleset_is_rejected():
    with pytest.raises(RulesetError):
        parse_ruleset({"jurisdiction": "x", "name": "x", "rules": [{"id": "A"}]})


def test_bad_severity_is_rejected():
    with pytest.raises(RulesetError):
        parse_ruleset(
            {
                "jurisdiction": "x",
                "name": "x",
                "rules": [
                    {
                        "id": "A",
                        "severity": "critical",
                        "title": "t",
                        "what": "w",
                        "fix": "f",
                        "citation": "c",
                        "check": {"type": "always"},
                    }
                ],
            }
        )


# ------------------------------------------------------------ message parsing


def test_headers_and_body_are_split():
    msg = parse_message("From: a@b.example\nSubject: Hello\n\nBody line.\n")
    assert msg.headers["from"] == "a@b.example"
    assert msg.subject == "Hello"
    assert msg.body.strip() == "Body line."


def test_body_only_file_has_no_headers():
    msg = parse_message("Hi there, this is the whole message.\n")
    assert msg.headers == {}
    assert msg.subject == ""
    assert "whole message" in msg.body


def test_folded_header_is_joined():
    msg = parse_message("Subject: a very long\n  subject line\n\nBody.\n")
    assert msg.subject == "a very long subject line"


def test_html_body_is_detected_and_stripped_for_matching():
    msg = parse_message('Subject: x\n\n<p>Hello <b>world</b></p>\n')
    assert msg.is_html
    assert "Hello" in msg.text and "<p>" not in msg.text


def test_links_are_collected_from_href_and_plain_text():
    msg = parse_message(
        'Subject: x\n\n<a href="https://a.example">a</a> and https://b.example\n'
    )
    assert "https://a.example" in msg.links()
    assert "https://b.example" in msg.links()


def test_image_count_counts_tags_and_bare_image_urls():
    msg = parse_message(
        'Subject: x\n\n<img src="https://a.example/1.png"> https://b.example/2.jpg\n'
    )
    assert msg.image_count() == 2

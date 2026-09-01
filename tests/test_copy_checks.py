"""Copy rules: each one firing, and each one staying quiet when satisfied."""

from __future__ import annotations

import pytest
from conftest import RULES_DIR

from coldsend_lint.copy_checks import run_copy_checks
from coldsend_lint.findings import exit_code
from coldsend_lint.message import load_message, parse_message
from coldsend_lint.rules import load_rulesets, select

ALL = ["us", "eu", "uk", "es", "ca"]


def lint(text: str, jurisdictions=ALL) -> list[str]:
    rulesets = load_rulesets(RULES_DIR)
    chosen, unknown = select(rulesets, list(jurisdictions))
    assert unknown == []
    return [f.id for f in run_copy_checks(parse_message(text), chosen)]


NAKED = "Subject: quick question\n\nHi, want to talk?\n"

COMPLIANT_TAIL = (
    "This is a commercial communication from Tinbridge Analytics Ltd. "
    "You requested this follow-up, we found your email address on your "
    "company's public contact page, and we write on the basis of our "
    "legitimate interest in B2B outreach. You have the right to object.\n"
    "Best,\nMarta Ellery\nTinbridge Analytics Ltd\n"
    "Unit 7, 42 Bellhaven Road, Reading, RG1 4QT, United Kingdom\n"
    "Privacy notice: https://tinbridge.example/privacy\n"
    "Unsubscribe: https://tinbridge.example/unsubscribe\n"
)


def compliant(subject: str = "The figures you asked for", body: str = "Hi Owen,\n") -> str:
    return f"From: Marta Ellery <marta@tinbridge.example>\nSubject: {subject}\n\n{body}\n{COMPLIANT_TAIL}"


# ------------------------------------------------------- unsubscribe rules


def test_missing_unsubscribe_fires_in_every_jurisdiction():
    fired = lint(NAKED)
    assert {"US-UNSUB-MISSING", "EU-UNSUB-MISSING", "UK-UNSUB-MISSING",
            "CA-UNSUB-MISSING", "ES-REVOCATION-CHANNEL-MISSING"} <= set(fired)


def test_unsubscribe_present_silences_the_missing_rules():
    fired = lint(compliant())
    assert not any("UNSUB-MISSING" in f for f in fired)
    assert "ES-REVOCATION-CHANNEL-MISSING" not in fired


def test_unsubscribe_without_a_link_is_not_actionable():
    text = NAKED + "\nTo unsubscribe, use the link below.\n\n{{unsubscribe_url}}\n"
    fired = lint(text)
    assert "US-UNSUB-NOT-ACTIONABLE" in fired
    assert "CA-UNSUB-NOT-READILY-PERFORMED" in fired


def test_unsubscribe_with_a_link_is_actionable():
    text = NAKED + "\nUnsubscribe: https://tinbridge.example/unsubscribe\n"
    assert "US-UNSUB-NOT-ACTIONABLE" not in lint(text)


def test_reply_stop_counts_as_an_actionable_optout():
    text = NAKED + "\nNot interested? Reply STOP and I will remove you.\n"
    assert "US-UNSUB-NOT-ACTIONABLE" not in lint(text)


def test_placeholder_unsubscribe_link_is_caught():
    text = (
        "Subject: hello\n\nHi.\n"
        'Unsubscribe: <a href="{{unsub}}">here</a>\n'
    )
    fired = lint(text)
    assert "US-UNSUB-NOT-ACTIONABLE" in fired


# ---------------------------------------------------------- postal address


@pytest.mark.parametrize(
    "address",
    [
        "118 Harbour Street, Suite 4, Portland, OR 97204",
        "Unit 7, 42 Bellhaven Road, Reading, RG1 4QT",
        "P.O. Box 1180, Toronto, M5V 3L9",
        "Calle Mayor 12, 28013 Madrid",
    ],
)
def test_postal_address_is_recognised(address):
    text = compliant(body=f"Hi Owen,\n{address}\n")
    assert "US-POSTAL-ADDRESS-MISSING" not in lint(text)


def test_missing_postal_address_fires_everywhere_it_is_required():
    fired = lint(NAKED)
    assert {"US-POSTAL-ADDRESS-MISSING", "UK-CONTACT-ADDRESS-MISSING",
            "CA-CONTACT-INFO-MISSING", "ES-POSTAL-ADDRESS-MISSING"} <= set(fired)


# -------------------------------------------------------- deceptive subject


@pytest.mark.parametrize("subject", ["Re: your invoice", "FWD: budget", "RE : hello", "Fw: hi"])
def test_fake_thread_prefix_fires(subject):
    assert "US-DECEPTIVE-THREAD-PREFIX" in lint(f"Subject: {subject}\n\nHi.\n")


def test_real_thread_prefix_does_not_fire():
    text = "Subject: Re: your invoice\nIn-Reply-To: <abc@mail.example>\n\nHi.\n"
    assert "US-DECEPTIVE-THREAD-PREFIX" not in lint(text)


def test_ordinary_subject_does_not_fire():
    assert "US-DECEPTIVE-THREAD-PREFIX" not in lint(NAKED)


# --------------------------------------------------------- sender identity


def test_anonymous_sender_fires_identity_rules_in_all_regimes():
    fired = lint("Subject: hi\n\nWe can help. https://x.example\n")
    assert {"US-SENDER-IDENTITY-UNCLEAR", "EU-CONTROLLER-IDENTITY-MISSING",
            "UK-IDENTITY-CONCEALED", "ES-ADVERTISER-NOT-IDENTIFIED",
            "CA-SENDER-NOT-IDENTIFIED"} <= set(fired)


def test_named_sender_with_company_passes():
    fired = lint(compliant())
    assert not any("IDENTITY" in f or "NOT-IDENTIFIED" in f for f in fired)


def test_signoff_without_any_company_still_fires():
    text = "Subject: hi\n\nHi there.\n\nBest,\nMarta\n"
    assert "US-SENDER-IDENTITY-UNCLEAR" in lint(text)


# ------------------------------------------------------- GDPR-family rules


def test_data_source_missing_fires():
    fired = lint(NAKED)
    assert {"EU-DATA-SOURCE-NOT-STATED", "ES-DATA-SOURCE-NOT-STATED",
            "UK-DATA-SOURCE-NOT-STATED"} <= set(fired)


def test_data_source_stated_passes():
    assert not any("DATA-SOURCE" in f for f in lint(compliant()))


def test_lawful_basis_missing_fires_and_stated_passes():
    assert "EU-LAWFUL-BASIS-NOT-STATED" in lint(NAKED)
    assert "EU-LAWFUL-BASIS-NOT-STATED" not in lint(compliant())


def test_privacy_notice_link_required():
    assert "EU-PRIVACY-NOTICE-MISSING" in lint(NAKED)
    assert "EU-PRIVACY-NOTICE-MISSING" not in lint(compliant())


def test_right_to_object_required():
    assert "EU-RIGHT-TO-OBJECT-MISSING" in lint(NAKED)
    assert "EU-RIGHT-TO-OBJECT-MISSING" not in lint(compliant())


# ------------------------------------------------- consent-regime specifics


def test_consent_not_evidenced_fires_for_es_and_ca():
    fired = lint(NAKED)
    assert "ES-CONSENT-NOT-EVIDENCED" in fired
    assert "CA-CONSENT-NOT-EVIDENCED" in fired


def test_consent_basis_stated_passes():
    fired = lint(compliant())
    assert "ES-CONSENT-NOT-EVIDENCED" not in fired
    assert "CA-CONSENT-NOT-EVIDENCED" not in fired


def test_spanish_publicidad_label():
    assert "ES-PUBLICIDAD-LABEL-MISSING" in lint(NAKED)
    assert "ES-PUBLICIDAD-LABEL-MISSING" not in lint(compliant())


def test_us_advertisement_disclosure():
    assert "US-ADVERTISEMENT-NOT-DISCLOSED" in lint(NAKED)
    assert "US-ADVERTISEMENT-NOT-DISCLOSED" not in lint(compliant())


def test_uk_sole_trader_advisory_is_always_emitted_as_info():
    rulesets = load_rulesets(RULES_DIR)
    chosen, _ = select(rulesets, ["uk"])
    findings = run_copy_checks(parse_message(compliant()), chosen)
    advisory = [f for f in findings if f.id == "UK-SOLE-TRADER-RISK"]
    assert advisory and advisory[0].severity == "info"


# ------------------------------------------- deliverability-adjacent copy


def test_merge_tags_are_caught_once_each():
    fired = lint("Subject: hi\n\nHello {{first_name}}, see %%OFFER%%.\n")
    assert fired.count("COPY-MERGE-TAG-UNMERGED") == 1


def test_clean_copy_has_no_merge_tag_finding():
    assert "COPY-MERGE-TAG-UNMERGED" not in lint(compliant())


def test_spam_trigger_cluster_fires_above_threshold():
    text = "Subject: hi\n\nAct now, limited time, click here for guaranteed results.\n"
    assert "COPY-SPAM-TRIGGER-PHRASES" in lint(text)


def test_one_spam_phrase_is_below_threshold():
    text = "Subject: hi\n\nThere is a limited time on the trial window.\n"
    assert "COPY-SPAM-TRIGGER-PHRASES" not in lint(text)


def test_shouting_on_punctuation_and_on_caps():
    assert "COPY-SHOUTING" in lint("Subject: hi\n\nRead this!!!\n")
    assert "COPY-SHOUTING" in lint("Subject: hi\n\nFREE MONEY TODAY offer.\n")
    assert "COPY-SHOUTING" not in lint(compliant())


def test_link_density():
    links = "\n".join(f"https://x.example/{i}" for i in range(5))
    assert "COPY-TOO-MANY-LINKS" in lint(f"Subject: hi\n\n{links}\n")
    assert "COPY-TOO-MANY-LINKS" not in lint(compliant())


def test_image_heavy_message():
    imgs = "".join(f'<img src="https://x.example/{i}.png">' for i in range(6))
    assert "COPY-IMAGE-HEAVY" in lint(f"Subject: hi\n\n<div>{imgs}</div>\n")


def test_image_with_almost_no_text():
    text = 'Subject: hi\n\n<p>Hi</p><img src="https://x.example/a.png">\n'
    assert "COPY-IMAGE-HEAVY" in lint(text)


def test_text_heavy_html_with_few_images_passes():
    body = "<p>" + ("Solid paragraph of real copy. " * 12) + "</p>"
    text = f'Subject: hi\n\n{body}<img src="https://x.example/a.png">\n'
    assert "COPY-IMAGE-HEAVY" not in lint(text)


# ------------------------------------------------------------- exit codes


def test_examples_good_and_bad(good_email, bad_email):
    rulesets = load_rulesets(RULES_DIR)
    chosen, _ = select(rulesets, ALL)

    good = run_copy_checks(load_message(good_email), chosen)
    assert exit_code(good) == 0
    assert [f.severity for f in good] == ["info"]

    bad = run_copy_checks(load_message(bad_email), chosen)
    assert exit_code(bad) == 2
    assert sum(1 for f in bad if f.severity == "error") >= 10


def test_warnings_only_gives_exit_code_1():
    """A message that satisfies every error rule but trips a warning."""
    text = compliant(body="Hi Owen,\n" + "\n".join(
        f"https://tinbridge.example/{i}" for i in range(4)
    ))
    rulesets = load_rulesets(RULES_DIR)
    chosen, _ = select(rulesets, ALL)
    findings = run_copy_checks(parse_message(text), chosen)
    assert [f.id for f in findings if f.severity == "error"] == []
    assert "COPY-TOO-MANY-LINKS" in [f.id for f in findings]
    assert exit_code(findings) == 1


# -------------------------------------------------------- rule coverage


def test_every_shipped_rule_is_exercised_by_this_suite():
    """No rule ships without a message in this file that makes it fire."""
    rulesets = load_rulesets(RULES_DIR)
    all_ids = {r.id for rs in rulesets.values() for r in rs.rules}

    corpus = [
        NAKED,
        compliant(),
        "Subject: Re: your invoice\n\nHi.\n",
        NAKED + "\nTo unsubscribe, use the link below.\n\n{{unsubscribe_url}}\n",
        "Subject: hi\n\nAct now, limited time, click here for guaranteed results!!!\n",
        "Subject: hi\n\n" + "\n".join(f"https://x.example/{i}" for i in range(5)),
        "Subject: hi\n\n" + "".join(
            f'<img src="https://x.example/{i}.png">' for i in range(6)
        ),
    ]
    chosen, _ = select(rulesets, ALL)
    fired: set[str] = set()
    for text in corpus:
        fired.update(f.id for f in run_copy_checks(parse_message(text), chosen))

    assert all_ids - fired == set(), f"rules never exercised: {sorted(all_ids - fired)}"

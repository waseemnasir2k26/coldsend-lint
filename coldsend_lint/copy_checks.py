"""The copy linter: runs YAML rules against a parsed message.

A rule's ``check.type`` names a function in ``CHECKS``. Every check returns
``(fired, evidence)``. ``fired`` True means the rule's finding is emitted.

Two generic types (``require_any``, ``forbid_any``) cover most rules from data
alone. The rest are builtins that need real logic (address shape, link density,
deceptive threading, and so on) and take their vocabulary from YAML params so a
non-English ruleset can supply its own words.
"""

from __future__ import annotations

import re
from typing import Callable

from .findings import Finding
from .message import Message, is_placeholder_link
from .rules import Rule, Ruleset

Check = Callable[[Message, dict], tuple[bool, list[str]]]

_TARGETS = {
    "subject": lambda m: m.subject,
    "body": lambda m: m.text,
    "raw_body": lambda m: m.body,
    "searchable": lambda m: m.searchable,
}


def normalize(text: str) -> str:
    """Collapse whitespace runs to single spaces.

    Rule patterns describe prose, not layout: a phrase that happens to wrap
    across two lines must still match.
    """
    return re.sub(r"\s+", " ", text).strip()


def _target_text(msg: Message, params: dict) -> str:
    name = params.get("target", "searchable")
    if name not in _TARGETS:
        raise ValueError(f"unknown check target {name!r}")
    return normalize(_TARGETS[name](msg))


def _compiled(params: dict, key: str = "patterns") -> list[re.Pattern[str]]:
    flags = 0 if params.get("case_sensitive") else re.IGNORECASE
    return [re.compile(p, flags) for p in params.get(key, [])]


def _matches(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        for m in pattern.finditer(text):
            snippet = m.group(0).strip()
            if snippet and snippet not in hits:
                hits.append(snippet)
    return hits


# --------------------------------------------------------------------------
# generic, data-driven checks
# --------------------------------------------------------------------------


def check_require_any(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires when NONE of the patterns appear."""
    text = _target_text(msg, params)
    hits = _matches(text, _compiled(params))
    return (not hits), ([] if hits else [f"none of {len(params.get('patterns', []))} expected phrasings found"])


def check_forbid_any(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires when ANY pattern appears."""
    text = _target_text(msg, params)
    hits = _matches(text, _compiled(params))
    return bool(hits), hits


def check_always(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Unconditional advisory (used for regime-mismatch notices)."""
    return True, list(params.get("evidence", []))


# --------------------------------------------------------------------------
# builtins
# --------------------------------------------------------------------------


def check_unsubscribe_present(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires when no opt-out wording of any kind is in the message."""
    hits = _matches(normalize(msg.searchable), _compiled(params, "keywords"))
    return (not hits), ([] if hits else ["no opt-out wording found in subject or body"])


def check_unsubscribe_actionable(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Opt-out wording exists but there is nothing the recipient can act on.

    Passes when the opt-out line carries a real URL / mailto, or when the
    message offers a reply-based opt-out ("reply STOP", "reply with UNSUBSCRIBE").
    Fires on placeholder links that were never merged.
    """
    keywords = _compiled(params, "keywords")
    if not _matches(normalize(msg.searchable), keywords):
        return False, []  # the "missing entirely" rule owns this case

    reply_patterns = _compiled(params, "reply_optout_patterns")
    if _matches(normalize(msg.searchable), reply_patterns):
        return False, []

    links = msg.links()
    real = [l for l in links if not is_placeholder_link(l)]
    placeholders = [l for l in links if is_placeholder_link(l)]

    if placeholders and not real:
        return True, [f"placeholder link never merged: {p}" for p in placeholders]
    if not links:
        return True, ["opt-out is mentioned but the message contains no link or mailto"]

    # Look for a link on or next to a line that mentions opting out.
    lines = msg.text.splitlines()
    for i, line in enumerate(lines):
        if not _matches(line, keywords):
            continue
        window = " ".join(lines[max(0, i - 1) : i + 2])
        raw_window = msg.body if msg.is_html else window
        if re.search(r"(https?://|mailto:)", window) or (
            msg.is_html and re.search(r"href", raw_window, re.I)
        ):
            return False, []
    return True, [
        "opt-out is mentioned but no link or mailto sits on or next to that line"
    ]


_STREET_RE = re.compile(
    r"\b\d{1,6}[A-Za-z]?\s+[\w.'-]+(?:\s+[\w.'-]+){0,3}\s+"
    r"(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct|"
    r"suite|ste|floor|fl|plaza|parkway|pkwy|square|sq|terrace|close|calle|carrer|"
    r"avenida|via|strasse|straße|weg)\b\.?",
    re.IGNORECASE,
)
_POSTCODE_RES = (
    re.compile(r"\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),  # US "CA 94107"
    re.compile(r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b"),  # UK "EC1A 1BB"
    re.compile(r"\b\d{5}\s+[A-ZÀ-Ü][\wà-ü'-]+", re.UNICODE),  # ES/DE
    re.compile(r"\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b"),  # CA "M5V 3L9"
)
_POBOX_RE = re.compile(r"\b(p\.?\s?o\.?\s?box|apartado de correos)\b", re.IGNORECASE)


def check_postal_address(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires when no physical postal address is detectable.

    Heuristic: a street-shaped line, a P.O. box, or a recognisable postcode.
    Deliberately generous — a false pass is possible, a false fail is loud.
    """
    text = normalize(msg.text)
    evidence: list[str] = []
    if m := _STREET_RE.search(text):
        evidence.append(m.group(0))
    if m := _POBOX_RE.search(text):
        evidence.append(m.group(0))
    for pattern in _POSTCODE_RES:
        if m := pattern.search(text):
            evidence.append(m.group(0))
            break
    if evidence:
        return False, evidence
    return True, ["no street line, P.O. box or postcode found in the body"]


_THREAD_HEADERS = ("in-reply-to", "references")
_FAKE_PREFIX_RE = re.compile(r"^\s*(re|fw|fwd)\s*(\[\d+\])?\s*:", re.IGNORECASE)


def check_deceptive_thread_prefix(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires on a Re:/Fwd: subject with no threading headers behind it."""
    subject = msg.subject
    if not _FAKE_PREFIX_RE.match(subject):
        return False, []
    if any(h in msg.headers for h in _THREAD_HEADERS):
        return False, []
    return True, [f"Subject: {subject.strip()}", "no In-Reply-To or References header"]


_COMPANY_RE = re.compile(
    r"\b(inc\.?|llc|l\.l\.c\.|ltd\.?|limited|gmbh|s\.?l\.?u?\.?|s\.?a\.?|b\.?v\.?|"
    r"pty|plc|oy|ab|a/s|corp\.?|corporation|company|co\.)\b",
    re.IGNORECASE,
)
_SIGNOFF_RE = re.compile(
    r"^\s*(--|—|best|regards|best regards|kind regards|thanks|thank you|cheers|"
    r"sincerely|warmly|un saludo|saludos|atentamente|cordialement)\b",
    re.IGNORECASE | re.MULTILINE,
)


def check_sender_identity(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires when the reader cannot tell who is writing or on whose behalf.

    Needs BOTH: a human sign-off or a named From, AND a company / website that
    identifies the sending organisation.
    """
    text = msg.text
    from_header = msg.sender
    named_from = bool(re.search(r"^[^<@]+<[^>]+>", from_header.strip()))
    has_signoff = bool(_SIGNOFF_RE.search(text))
    has_company = bool(_COMPANY_RE.search(text)) or bool(
        re.search(r"https?://|www\.", text)
    )

    missing: list[str] = []
    if not (named_from or has_signoff):
        missing.append("no display-name From header and no sign-off / signature block")
    if not has_company:
        missing.append("no company name or website identifying the sender's business")
    return bool(missing), missing


def check_spam_triggers(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Fires when the message uses at least ``threshold`` spam-trigger phrases."""
    threshold = int(params.get("threshold", 3))
    hits = _matches(normalize(msg.searchable), _compiled(params, "phrases"))
    return (len(hits) >= threshold), hits


def check_shouting(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """ALL-CAPS words and !!!! runs in the subject or body."""
    min_caps = int(params.get("min_caps_words", 3))
    allow = {w.upper() for w in params.get("allow", ())}
    text = msg.searchable
    caps = [w for w in re.findall(r"\b[A-Z]{4,}\b", text) if w not in allow]
    bangs = re.findall(r"[!?]{2,}", text)
    evidence: list[str] = []
    if len(caps) >= min_caps:
        evidence.append(f"ALL-CAPS words: {', '.join(sorted(set(caps))[:8])}")
    if bangs:
        evidence.append(f"repeated punctuation: {', '.join(sorted(set(bangs))[:5])}")
    return bool(evidence), evidence


def check_link_density(msg: Message, params: dict) -> tuple[bool, list[str]]:
    max_links = int(params.get("max_links", 3))
    links = msg.links()
    if len(links) <= max_links:
        return False, []
    return True, [f"{len(links)} links (limit {max_links})", *links[:8]]


def check_image_ratio(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Image-heavy, text-light mail is a classic filter trigger."""
    min_chars = int(params.get("min_text_chars", 250))
    max_images = int(params.get("max_images", 4))
    images = msg.image_count()
    chars = msg.text_length()
    evidence: list[str] = []
    if images > max_images:
        evidence.append(f"{images} images (limit {max_images})")
    if images >= 1 and chars < min_chars:
        evidence.append(f"only {chars} characters of text alongside {images} image(s)")
    return bool(evidence), evidence


def check_broken_merge_tags(msg: Message, params: dict) -> tuple[bool, list[str]]:
    """Unmerged personalisation tokens that survived into the final copy."""
    hits = _matches(msg.raw, _compiled(params, "patterns"))
    return bool(hits), hits


CHECKS: dict[str, Check] = {
    "require_any": check_require_any,
    "forbid_any": check_forbid_any,
    "always": check_always,
    "unsubscribe_present": check_unsubscribe_present,
    "unsubscribe_actionable": check_unsubscribe_actionable,
    "postal_address": check_postal_address,
    "deceptive_thread_prefix": check_deceptive_thread_prefix,
    "sender_identity": check_sender_identity,
    "spam_triggers": check_spam_triggers,
    "shouting": check_shouting,
    "link_density": check_link_density,
    "image_ratio": check_image_ratio,
    "broken_merge_tags": check_broken_merge_tags,
}


def run_rule(msg: Message, rule: Rule, jurisdiction: str) -> Finding | None:
    params = dict(rule.check)
    check_type = params.pop("type")
    if check_type not in CHECKS:
        raise ValueError(f"rule {rule.id}: unknown check type {check_type!r}")
    fired, evidence = CHECKS[check_type](msg, params)
    if not fired:
        return None
    return Finding(
        id=rule.id,
        severity=rule.severity,
        category=rule.category,
        jurisdiction=jurisdiction,
        title=rule.title,
        detail=rule.what,
        fix=rule.fix,
        citation=rule.citation,
        evidence=evidence,
    )


def run_copy_checks(msg: Message, rulesets: list[Ruleset]) -> list[Finding]:
    findings: list[Finding] = []
    for ruleset in rulesets:
        code = "-" if ruleset.always else ruleset.jurisdiction.upper()
        for rule in ruleset.rules:
            finding = run_rule(msg, rule, code)
            if finding is not None:
                findings.append(finding)
    return findings

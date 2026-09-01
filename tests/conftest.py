from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from coldsend_lint.rules import load_rulesets  # noqa: E402

RULES_DIR = ROOT / "rules"
EXAMPLES = ROOT / "examples"


@pytest.fixture(scope="session")
def rulesets():
    return load_rulesets(RULES_DIR)


@pytest.fixture(scope="session")
def good_email() -> Path:
    return EXAMPLES / "good-email.txt"


@pytest.fixture(scope="session")
def bad_email() -> Path:
    return EXAMPLES / "bad-email.txt"


def healthy_dns(domain: str = "tinbridge.example", ip: str = "203.0.113.10") -> dict:
    """A DNS zone that passes every deliverability check."""
    host = f"mail.{domain}"
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    return {
        (domain, "MX"): [f"10 {host}"],
        (domain, "TXT"): ["v=spf1 include:_spf.example.net -all"],
        (f"default._domainkey.{domain}", "TXT"): ["v=DKIM1; k=rsa; p=" + "A" * 392],
        (f"_dmarc.{domain}", "TXT"): [
            "v=DMARC1; p=reject; rua=mailto:dmarc@" + domain
        ],
        (rev, "PTR"): [host],
        (host, "A"): [ip],
    }

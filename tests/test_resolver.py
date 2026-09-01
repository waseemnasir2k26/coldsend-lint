from __future__ import annotations

import pytest

from coldsend_lint.resolver import (
    DNSTimeout,
    FakeResolver,
    NoAnswer,
    NXDomain,
    reverse_name,
    reversed_octets,
)


def test_reverse_name():
    assert reverse_name("203.0.113.10") == "10.113.0.203.in-addr.arpa"
    assert reversed_octets("203.0.113.10") == "10.113.0.203"


@pytest.mark.parametrize("bad", ["", "203.0.113", "203.0.113.999", "not-an-ip", "::1"])
def test_reverse_name_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        reverse_name(bad)


def test_fake_resolver_returns_records():
    r = FakeResolver({("example.test", "TXT"): ["v=spf1 -all"]})
    assert r.resolve("example.test", "TXT") == ["v=spf1 -all"]
    assert r.queries == [("example.test", "TXT")]


def test_fake_resolver_is_case_and_dot_insensitive():
    r = FakeResolver({("example.test", "MX"): ["10 mail.example.test"]})
    assert r.resolve("EXAMPLE.TEST.", "mx") == ["10 mail.example.test"]


def test_fake_resolver_no_answer_vs_nxdomain():
    r = FakeResolver({("example.test", "MX"): ["10 mail.example.test"]})
    with pytest.raises(NoAnswer):
        r.resolve("example.test", "TXT")
    with pytest.raises(NXDomain):
        r.resolve("other.test", "TXT")


def test_fake_resolver_timeout():
    r = FakeResolver({}, timeouts={"slow.test"})
    with pytest.raises(DNSTimeout):
        r.resolve("slow.test", "TXT")


def test_real_resolver_is_never_imported_by_the_checks():
    """dns_checks must not import dnspython, or tests would need a network."""
    import inspect

    from coldsend_lint import dns_checks

    source = inspect.getsource(dns_checks)
    assert "import dns" not in source

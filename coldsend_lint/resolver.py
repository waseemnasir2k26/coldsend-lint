"""Resolver interface + a fake resolver, so every DNS check is offline-testable.

Nothing in ``dns_checks.py`` imports dnspython directly. It only ever talks to
this interface, which means the whole test suite runs with zero network.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class DNSError(Exception):
    """Base for resolver problems."""


class NXDomain(DNSError):
    """The name does not exist."""


class NoAnswer(DNSError):
    """The name exists but has no record of the requested type."""


class DNSTimeout(DNSError):
    """The query timed out or no nameserver answered."""


@runtime_checkable
class Resolver(Protocol):
    def resolve(self, name: str, rdtype: str) -> list[str]:
        """Return record values as strings.

        TXT values are returned already joined and unquoted. MX values are
        returned as ``"<pref> <exchange>"``. Raises NXDomain / NoAnswer /
        DNSTimeout.
        """


def reverse_name(ip: str) -> str:
    """IPv4 dotted-quad -> in-addr.arpa name. Raises ValueError on bad input."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"not an IPv4 address: {ip!r}")
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            raise ValueError(f"not an IPv4 address: {ip!r}")
    return ".".join(reversed(parts)) + ".in-addr.arpa"


def reversed_octets(ip: str) -> str:
    """IPv4 -> reversed octets, the prefix used for DNSBL lookups."""
    return reverse_name(ip)[: -len(".in-addr.arpa")]


class FakeResolver:
    """Deterministic in-memory resolver for tests and dry runs.

    ``records`` maps ``(name.lower(), RDTYPE)`` to a list of strings. A name
    present under any type but missing the requested type raises NoAnswer; a
    name absent entirely raises NXDomain. Names listed in ``timeouts`` raise
    DNSTimeout.
    """

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
        timeouts: set[str] | None = None,
    ) -> None:
        self.records: dict[tuple[str, str], list[str]] = {}
        for (name, rdtype), values in (records or {}).items():
            self.records[(name.lower().rstrip("."), rdtype.upper())] = list(values)
        self.timeouts = {t.lower().rstrip(".") for t in (timeouts or set())}
        self.queries: list[tuple[str, str]] = []

    def resolve(self, name: str, rdtype: str) -> list[str]:
        key_name = name.lower().rstrip(".")
        rdtype = rdtype.upper()
        self.queries.append((key_name, rdtype))
        if key_name in self.timeouts:
            raise DNSTimeout(f"timeout resolving {name} {rdtype}")
        if (key_name, rdtype) in self.records:
            return list(self.records[(key_name, rdtype)])
        if any(n == key_name for n, _ in self.records):
            raise NoAnswer(f"no {rdtype} record for {name}")
        raise NXDomain(f"{name} does not exist")


class DnsPythonResolver:
    """Real resolver. dnspython is imported lazily so tests never need it."""

    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None) -> None:
        import dns.resolver  # noqa: PLC0415  (lazy on purpose)

        self._r = dns.resolver.Resolver()
        self._r.timeout = timeout
        self._r.lifetime = timeout
        if nameservers:
            self._r.nameservers = list(nameservers)

    def resolve(self, name: str, rdtype: str) -> list[str]:
        import dns.resolver  # noqa: PLC0415
        import dns.rdatatype  # noqa: PLC0415

        try:
            answer = self._r.resolve(name, rdtype)
        except dns.resolver.NXDOMAIN as exc:
            raise NXDomain(str(exc)) from exc
        except dns.resolver.NoAnswer as exc:
            raise NoAnswer(str(exc)) from exc
        except (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as exc:
            raise DNSTimeout(str(exc)) from exc

        out: list[str] = []
        for rdata in answer:
            if rdtype.upper() == "TXT":
                chunks = getattr(rdata, "strings", None)
                if chunks is not None:
                    out.append("".join(c.decode("utf-8", "replace") for c in chunks))
                else:  # pragma: no cover - defensive
                    out.append(str(rdata).strip('"'))
            elif rdtype.upper() == "MX":
                out.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            else:
                out.append(str(rdata).rstrip("."))
        return out

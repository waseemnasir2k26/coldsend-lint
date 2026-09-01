"""Deliverability checks: MX, SPF, DKIM selector discovery, DMARC, PTR, DNSBL.

Every function takes a Resolver, so the whole module is testable offline.
"""

from __future__ import annotations

import re

from .findings import Finding
from .resolver import (
    DNSError,
    DNSTimeout,
    NoAnswer,
    NXDomain,
    Resolver,
    reverse_name,
    reversed_octets,
)

# Selectors used by the mainstream senders. Cold-email stacks are almost always
# one of these; anything else has to be passed with --dkim-selector.
DEFAULT_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "sendgrid",
    "zoho",
    "protonmail",
    "mailjet",
    "pm",
    "sm",
)

# Zones that answer for free and are widely honoured. Point-in-time only.
DEFAULT_DNSBL_ZONES = (
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
)

_CITE_RFC7208 = "RFC 7208 (SPF)"
_CITE_RFC6376 = "RFC 6376 (DKIM)"
_CITE_RFC7489 = "RFC 7489 (DMARC)"
_CITE_RFC5321 = "RFC 5321 sec. 5.1 (mail routing / MX)"


def _F(**kw) -> Finding:
    kw.setdefault("category", "deliverability")
    kw.setdefault("jurisdiction", "-")
    kw.setdefault("evidence", [])
    return Finding(**kw)


def _txt(resolver: Resolver, name: str) -> list[str]:
    return resolver.resolve(name, "TXT")


def _timeout_finding(fid: str, what: str, name: str, exc: Exception) -> Finding:
    return _F(
        id=fid,
        severity="warn",
        title=f"{what} lookup timed out",
        detail=f"No answer for {name}: {exc}",
        fix="Re-run when DNS is reachable; this check was inconclusive.",
        citation="-",
    )


def check_mx(resolver: Resolver, domain: str) -> list[Finding]:
    try:
        records = resolver.resolve(domain, "MX")
    except (NoAnswer, NXDomain) as exc:
        return [
            _F(
                id="DNS-MX-MISSING",
                severity="error",
                title="No MX record",
                detail=f"{domain} publishes no MX record ({exc.__class__.__name__}). "
                "Replies to your campaign have nowhere to land, and many receivers "
                "reject mail from domains that cannot receive it.",
                fix="Publish at least one MX record pointing at the mailbox host you "
                "actually read replies on.",
                citation=_CITE_RFC5321,
            )
        ]
    except DNSTimeout as exc:
        return [_timeout_finding("DNS-MX-TIMEOUT", "MX", domain, exc)]

    if not records:
        return [
            _F(
                id="DNS-MX-MISSING",
                severity="error",
                title="No MX record",
                detail=f"{domain} returned an empty MX set.",
                fix="Publish an MX record for the domain you send from.",
                citation=_CITE_RFC5321,
            )
        ]
    return [
        _F(
            id="DNS-MX-OK",
            severity="info",
            title="MX present",
            detail=f"{len(records)} MX record(s) found.",
            fix="No action.",
            citation=_CITE_RFC5321,
            evidence=sorted(records),
        )
    ]


def _spf_lookup_count(record: str) -> int:
    """Count mechanisms that trigger a DNS lookup. Static: includes are not expanded."""
    count = 0
    for token in record.split():
        low = token.lower().lstrip("+-~?")
        if low.startswith(("include:", "exists:", "redirect=")):
            count += 1
        elif low == "a" or low.startswith(("a:", "a/")):
            count += 1
        elif low == "mx" or low.startswith(("mx:", "mx/")):
            count += 1
        elif low == "ptr" or low.startswith("ptr:"):
            count += 1
    return count


def check_spf(resolver: Resolver, domain: str) -> list[Finding]:
    try:
        values = _txt(resolver, domain)
    except (NoAnswer, NXDomain):
        values = []
    except DNSTimeout as exc:
        return [_timeout_finding("DNS-SPF-TIMEOUT", "TXT (SPF)", domain, exc)]

    spf = [v for v in values if v.strip().lower().startswith("v=spf1")]
    if not spf:
        return [
            _F(
                id="DNS-SPF-MISSING",
                severity="error",
                title="No SPF record",
                detail=f"No v=spf1 TXT record on {domain}. Cold volume from an "
                "SPF-less domain is treated as unauthenticated by most receivers.",
                fix="Publish a TXT record such as "
                "v=spf1 include:<your-esp> -all listing every service that sends "
                "as this domain.",
                citation=_CITE_RFC7208,
            )
        ]

    out: list[Finding] = []
    if len(spf) > 1:
        out.append(
            _F(
                id="DNS-SPF-MULTIPLE",
                severity="error",
                title="More than one SPF record",
                detail=f"{len(spf)} v=spf1 records found. SPF evaluation returns "
                "PERMERROR when a domain publishes more than one, so SPF fails "
                "outright.",
                fix="Merge them into a single TXT record.",
                citation="RFC 7208 sec. 4.5",
                evidence=spf,
            )
        )

    record = spf[0]
    tokens = record.split()
    all_token = next((t for t in tokens if t.lower().endswith("all")), None)
    if all_token is None:
        out.append(
            _F(
                id="DNS-SPF-NO-ALL",
                severity="warn",
                title="SPF record has no 'all' mechanism",
                detail="Without a terminating 'all', receivers get NEUTRAL for every "
                "sender you did not list.",
                fix="End the record with -all (hard fail) or at minimum ~all.",
                citation="RFC 7208 sec. 5.1",
                evidence=[record],
            )
        )
    elif all_token.lower() in ("+all", "all"):
        out.append(
            _F(
                id="DNS-SPF-PLUS-ALL",
                severity="error",
                title="SPF record ends in +all",
                detail="+all authorises the entire internet to send as your domain. "
                "It is worse than having no SPF at all.",
                fix="Replace +all with -all (or ~all while you are still "
                "inventorying senders).",
                citation="RFC 7208 sec. 5.1",
                evidence=[record],
            )
        )
    elif all_token.lower() == "?all":
        out.append(
            _F(
                id="DNS-SPF-NEUTRAL-ALL",
                severity="warn",
                title="SPF record ends in ?all (neutral)",
                detail="?all tells receivers to treat unlisted senders as neutral, "
                "which gives you no protection against spoofing of your domain.",
                fix="Move to ~all, then -all once you have inventoried senders.",
                citation="RFC 7208 sec. 5.1",
                evidence=[record],
            )
        )

    lookups = _spf_lookup_count(record)
    if lookups > 10:
        out.append(
            _F(
                id="DNS-SPF-TOO-MANY-LOOKUPS",
                severity="error",
                title=f"SPF exceeds the 10 DNS-lookup limit ({lookups} counted)",
                detail="SPF evaluation must not require more than 10 DNS lookups. "
                "Over the limit the result is PERMERROR and SPF is treated as failing.",
                fix="Flatten or drop include: mechanisms until the count is 10 or "
                "fewer. Counted statically here, so nested includes may push the real "
                "figure higher.",
                citation="RFC 7208 sec. 4.6.4",
                evidence=[record, f"lookup mechanisms counted: {lookups}"],
            )
        )
    elif lookups >= 9:
        out.append(
            _F(
                id="DNS-SPF-LOOKUPS-NEAR-LIMIT",
                severity="warn",
                title=f"SPF is close to the 10-lookup limit ({lookups} counted)",
                detail="This count is static (nested includes are not expanded), so "
                "the real total may already exceed 10.",
                fix="Reduce include: mechanisms or flatten them to IP ranges.",
                citation="RFC 7208 sec. 4.6.4",
                evidence=[record],
            )
        )

    if not any(f.severity in ("error", "warn") for f in out):
        out.append(
            _F(
                id="DNS-SPF-OK",
                severity="info",
                title="SPF present and terminated",
                detail=f"SPF found with {lookups} DNS-lookup mechanism(s).",
                fix="No action.",
                citation=_CITE_RFC7208,
                evidence=[record],
            )
        )
    return out


def check_dkim(
    resolver: Resolver,
    domain: str,
    selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS,
) -> list[Finding]:
    found: list[str] = []
    weak: list[str] = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            values = _txt(resolver, name)
        except DNSError:
            continue
        for value in values:
            if "p=" not in value:
                continue
            found.append(f"{selector}: {value[:120]}")
            key = re.search(r"\bp=([A-Za-z0-9+/=]*)", value)
            if key is None:
                continue
            if key.group(1) == "":
                weak.append(f"{selector}: revoked key (p= is empty)")
            elif len(key.group(1)) < 200:
                weak.append(f"{selector}: key looks shorter than 1024-bit")

    if not found:
        return [
            _F(
                id="DNS-DKIM-NOT-FOUND",
                severity="error",
                title="No DKIM key found",
                detail=f"None of the {len(selectors)} probed selectors returned a key "
                f"at <selector>._domainkey.{domain}. DKIM selectors cannot be "
                "enumerated from DNS, so this means 'not found', not proof of absence.",
                fix="Enable DKIM signing at your sending provider and publish the "
                "selector record. Re-run with --dkim-selector <name> if you use a "
                "custom selector.",
                citation=_CITE_RFC6376,
                evidence=[f"probed: {', '.join(selectors)}"],
            )
        ]

    out = [
        _F(
            id="DNS-DKIM-OK",
            severity="info",
            title=f"DKIM key found on {len(found)} selector(s)",
            detail="At least one selector publishes a public key.",
            fix="No action.",
            citation=_CITE_RFC6376,
            evidence=found,
        )
    ]
    if weak:
        out.append(
            _F(
                id="DNS-DKIM-WEAK-KEY",
                severity="warn",
                title="A DKIM selector looks revoked or under-sized",
                detail="A published key is empty (revoked) or shorter than a 1024-bit "
                "RSA key would be.",
                fix="Rotate to a 2048-bit key and remove revoked selectors.",
                citation="RFC 8301 (DKIM crypto update)",
                evidence=weak,
            )
        )
    return out


def _parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(resolver: Resolver, domain: str) -> list[Finding]:
    name = f"_dmarc.{domain}"
    try:
        values = _txt(resolver, name)
    except (NoAnswer, NXDomain):
        values = []
    except DNSTimeout as exc:
        return [_timeout_finding("DNS-DMARC-TIMEOUT", "TXT (DMARC)", name, exc)]

    dmarc = [v for v in values if v.strip().lower().startswith("v=dmarc1")]
    if not dmarc:
        return [
            _F(
                id="DNS-DMARC-MISSING",
                severity="error",
                title="No DMARC record",
                detail=f"No v=DMARC1 TXT record at {name}. Since February 2024 "
                "Google and Yahoo require a DMARC record from bulk senders.",
                fix="Publish v=DMARC1; p=none; rua=mailto:dmarc@<your-domain> to "
                "start collecting reports, then move to p=quarantine and p=reject.",
                citation=_CITE_RFC7489,
            )
        ]

    record = dmarc[0]
    tags = _parse_dmarc(record)
    out: list[Finding] = []
    policy = tags.get("p", "").lower()

    if policy == "none":
        out.append(
            _F(
                id="DNS-DMARC-POLICY-NONE",
                severity="warn",
                title="DMARC policy is p=none",
                detail="Monitoring only. Nobody is stopped from spoofing your domain, "
                "and some receivers treat p=none as an unfinished setup.",
                fix="Once your reports are clean, move to p=quarantine and then "
                "p=reject.",
                citation="RFC 7489 sec. 6.3",
                evidence=[record],
            )
        )
    elif policy not in ("quarantine", "reject"):
        out.append(
            _F(
                id="DNS-DMARC-POLICY-INVALID",
                severity="error",
                title="DMARC record has no valid p= policy",
                detail=f"p= is {policy or 'absent'}; the tag is required and must be "
                "none, quarantine or reject.",
                fix="Add a valid p= tag.",
                citation="RFC 7489 sec. 6.3",
                evidence=[record],
            )
        )

    if "rua" not in tags:
        out.append(
            _F(
                id="DNS-DMARC-NO-RUA",
                severity="warn",
                title="DMARC has no aggregate-report address",
                detail="Without rua= you get no visibility into who is sending as "
                "your domain or whether your own mail is aligning.",
                fix="Add rua=mailto:dmarc@<your-domain>.",
                citation="RFC 7489 sec. 6.3",
                evidence=[record],
            )
        )

    if not out:
        out.append(
            _F(
                id="DNS-DMARC-OK",
                severity="info",
                title=f"DMARC present with p={policy}",
                detail="Policy is enforcing and reporting is configured.",
                fix="No action.",
                citation=_CITE_RFC7489,
                evidence=[record],
            )
        )
    return out


def check_ptr(resolver: Resolver, ip: str) -> list[Finding]:
    try:
        rname = reverse_name(ip)
    except ValueError as exc:
        return [
            _F(
                id="DNS-PTR-BAD-IP",
                severity="error",
                title="Sending IP is not a valid IPv4 address",
                detail=str(exc),
                fix="Pass the public IPv4 address your MTA sends from via --ip.",
                citation="RFC 1912 sec. 2.1",
            )
        ]

    try:
        ptrs = resolver.resolve(rname, "PTR")
    except (NoAnswer, NXDomain):
        return [
            _F(
                id="DNS-PTR-MISSING",
                severity="error",
                title="Sending IP has no PTR record",
                detail=f"{ip} has no reverse DNS. Several large receivers reject or "
                "heavily penalise mail from IPs without a PTR.",
                fix="Ask your host or ESP to set reverse DNS for the IP to a hostname "
                "that also resolves forward to the same IP.",
                citation="RFC 1912 sec. 2.1",
            )
        ]
    except DNSTimeout as exc:
        return [_timeout_finding("DNS-PTR-TIMEOUT", "PTR", rname, exc)]

    hostname = ptrs[0]
    try:
        forward = resolver.resolve(hostname, "A")
    except DNSError:
        forward = []

    if ip not in forward:
        return [
            _F(
                id="DNS-PTR-NO-FORWARD-CONFIRM",
                severity="warn",
                title="PTR does not forward-confirm",
                detail=f"{ip} -> {hostname}, but {hostname} does not resolve back to "
                f"{ip}. Receivers that run FCrDNS will treat the IP as unverified.",
                fix=f"Add an A record for {hostname} pointing at {ip}.",
                citation="RFC 1912 sec. 2.1",
                evidence=[f"PTR: {hostname}", f"A: {', '.join(forward) or 'none'}"],
            )
        ]

    return [
        _F(
            id="DNS-PTR-OK",
            severity="info",
            title="PTR present and forward-confirmed",
            detail=f"{ip} <-> {hostname}",
            fix="No action.",
            citation="RFC 1912 sec. 2.1",
            evidence=[hostname],
        )
    ]


def check_dnsbl(
    resolver: Resolver,
    ip: str,
    zones: tuple[str, ...] = DEFAULT_DNSBL_ZONES,
) -> list[Finding]:
    try:
        prefix = reversed_octets(ip)
    except ValueError as exc:
        return [
            _F(
                id="DNS-BL-BAD-IP",
                severity="error",
                title="Cannot run blacklist checks: invalid IP",
                detail=str(exc),
                fix="Pass a public IPv4 address via --ip.",
                citation="DNSBL convention (RFC 5782)",
            )
        ]

    listed: list[str] = []
    unreachable: list[str] = []
    for zone in zones:
        try:
            answers = resolver.resolve(f"{prefix}.{zone}", "A")
        except (NXDomain, NoAnswer):
            continue  # not listed
        except DNSTimeout:
            unreachable.append(zone)
            continue
        if answers:
            listed.append(f"{zone} -> {', '.join(answers)}")

    out: list[Finding] = []
    if listed:
        out.append(
            _F(
                id="DNS-BL-LISTED",
                severity="error",
                title=f"Sending IP is listed on {len(listed)} blacklist(s)",
                detail=f"{ip} is currently listed. Expect bulk-foldering or outright "
                "rejection until you delist.",
                fix="Stop sending from this IP, fix the cause (compromised account, "
                "bad list, spam traps), then request delisting on each zone's site.",
                citation="DNSBL lookup (RFC 5782)",
                evidence=listed,
            )
        )
    else:
        out.append(
            _F(
                id="DNS-BL-CLEAN",
                severity="info",
                title="Sending IP is not listed on the checked blacklists",
                detail=f"Checked {len(zones)} zone(s). This is point-in-time only and "
                "says nothing about reputation systems that do not publish a DNSBL.",
                fix="No action.",
                citation="DNSBL lookup (RFC 5782)",
                evidence=list(zones),
            )
        )
    if unreachable:
        out.append(
            _F(
                id="DNS-BL-UNREACHABLE",
                severity="warn",
                title="Some blacklist zones did not answer",
                detail="These zones timed out, so their result is unknown. Public "
                "mirrors also block queries coming from large public resolvers.",
                fix="Re-run from a host with its own resolver, or use a paid data feed.",
                citation="DNSBL lookup (RFC 5782)",
                evidence=unreachable,
            )
        )
    return out


def run_dns_checks(
    resolver: Resolver,
    domain: str,
    ip: str | None = None,
    dkim_selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS,
    dnsbl_zones: tuple[str, ...] = DEFAULT_DNSBL_ZONES,
    skip_dnsbl: bool = False,
) -> list[Finding]:
    domain = domain.strip().rstrip(".").lower()
    findings = [
        *check_mx(resolver, domain),
        *check_spf(resolver, domain),
        *check_dkim(resolver, domain, dkim_selectors),
        *check_dmarc(resolver, domain),
    ]
    if ip:
        findings += check_ptr(resolver, ip)
        if not skip_dnsbl:
            findings += check_dnsbl(resolver, ip, dnsbl_zones)
    else:
        findings.append(
            _F(
                id="DNS-PTR-SKIPPED",
                severity="info",
                title="PTR and blacklist checks skipped",
                detail="No sending IP given, so reverse DNS and DNSBL were not checked.",
                fix="Re-run with --ip <your sending IPv4> to include them.",
                citation="-",
            )
        )
    return findings

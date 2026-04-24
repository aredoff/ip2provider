from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.resolver
import tldextract
from ipwhois import IPWhois

_PATTERNS: Optional[tldextract.TLDExtract] = None

_EMAIL_IN_TEXT = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)


def _tld() -> tldextract.TLDExtract:
    global _PATTERNS
    if _PATTERNS is None:
        _PATTERNS = tldextract.TLDExtract(
            include_psl_private_domains=True,
        )
    return _PATTERNS


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def is_global_unicast_ip(s: str) -> bool:
    try:
        return bool(ipaddress.ip_address(s).is_global)
    except ValueError:
        return False


def _unique_preserve_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        k = x.strip().rstrip(".")
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


def _walk_emails(obj: Any, out: Set[str]) -> None:
    if obj is None:
        return
    if isinstance(obj, str):
        for m in _EMAIL_IN_TEXT.findall(obj):
            out.add(m.lower())
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_emails(v, out)
        return
    if isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_emails(v, out)


def _norm_asn_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).upper().replace("AS", "").strip()
    return s if s.isdigit() else None


def _organization_from_rdap(data: dict) -> Optional[str]:
    objs = data.get("objects")
    if not isinstance(objs, dict):
        return None
    abuse_org: Optional[str] = None
    for _h, ent in objs.items():
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles") or []
        cont = ent.get("contact")
        if not isinstance(cont, dict):
            continue
        nm = cont.get("name")
        if not isinstance(nm, str) or not nm.strip():
            continue
        t = nm.strip()
        if "registrant" in roles:
            return t
        if "abuse" in roles and " - " in t:
            abuse_org = t.split(" - ")[0].strip()
    return abuse_org


def _rdap_for_ip(
    ip: str,
    *,
    timeout: int = 10,
) -> Tuple[
    Optional[str],
    List[str],
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[Dict[str, Any]],
]:
    if not is_global_unicast_ip(ip):
        return None, [], None, None, None, None
    t = int(min(max(timeout, 1), 60))
    try:
        data = IPWhois(ip, timeout=t).lookup_rdap(depth=1)
    except Exception as e:
        return None, [], None, None, None, {
            "error": str(e),
            "ip": ip,
            "source": "rdap",
        }
    net = data.get("network") or {}
    netname = None
    if isinstance(net, dict):
        netname = net.get("name") or net.get("handle")
    asn_desc = data.get("asn_description")
    asn = _norm_asn_str(data.get("asn"))
    org = _organization_from_rdap(data) if isinstance(data, dict) else None
    emails: Set[str] = set()
    _walk_emails(data, emails)
    ne = sorted(emails)
    return (
        str(netname) if netname else None,
        ne,
        str(asn_desc) if asn_desc else None,
        asn,
        org,
        data,
    )


def _dns_lookup_a_aaaa(
    name: str,
    resolver: dns.resolver.Resolver,
) -> List[str]:
    ips: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ans = resolver.resolve(name, rtype)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            OSError,
            dns.name.LabelTooLong,
            dns.name.EmptyLabel,
        ):
            continue
        except Exception:
            continue
        for r in ans:
            if rtype == "A":
                ips.append(r.address)
            else:
                ips.append(r.address)
    return _unique_preserve_order(ips)


def _dns_ptr(ip: str, resolver: dns.resolver.Resolver) -> List[str]:
    try:
        rev = dns.reversename.from_address(ip)
        ans = resolver.resolve(rev, "PTR")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        OSError,
        ValueError,
        dns.name.LabelTooLong,
    ):
        return []
    except Exception:
        return []
    return _unique_preserve_order([str(r.target).rstrip(".") for r in ans])


def _registered_domain(fqdn: str) -> str:
    try:
        ext = _tld()(fqdn)
    except Exception:
        return fqdn.rstrip(".").lower()
    if not ext.suffix:
        return fqdn.rstrip(".").lower()
    reg = f"{ext.domain}.{ext.suffix}".lower()
    return reg if ext.domain else fqdn.rstrip(".").lower()


def _dns_ns_for_domain(
    domain: str,
    resolver: dns.resolver.Resolver,
) -> List[str]:
    try:
        ans = resolver.resolve(domain, "NS")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        OSError,
        dns.name.LabelTooLong,
    ):
        return []
    except Exception:
        return []
    return _unique_preserve_order([str(r.target).rstrip(".") for r in ans])


@dataclass
class CollectedEvidence:
    target: str
    input_kind: str
    derived_ips: List[str] = field(default_factory=list)
    fqdn_hints: List[str] = field(default_factory=list)
    network_name: Optional[str] = None
    network_contact_emails: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    asn_description: Optional[str] = None
    organization: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    zone: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    raw_rdap: Optional[Dict[str, Any]] = None

    def to_find_kwargs(
        self,
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.derived_ips:
            if len(self.derived_ips) == 1:
                out["ip"] = self.derived_ips[0]
            out["ips"] = list(self.derived_ips)
        if self.fqdn_hints:
            if len(self.fqdn_hints) == 1:
                out["fqdn"] = self.fqdn_hints[0]
            out["fqdns"] = list(self.fqdn_hints)
        if self.network_name:
            out["network_name"] = self.network_name
        if self.network_contact_emails:
            if len(self.network_contact_emails) == 1:
                out["network_contact_email"] = self.network_contact_emails[0]
            out["network_contact_emails"] = list(self.network_contact_emails)
        if self.nameservers:
            if len(self.nameservers) == 1:
                out["ns_server"] = self.nameservers[0]
            out["ns_servers"] = list(self.nameservers)
        if self.asn:
            out["asn"] = self.asn
        if self.asn_description:
            out["asname"] = self.asn_description
        if self.organization:
            out["organization"] = self.organization
        return out


def collect_evidence(
    target: str,
    *,
    dns_timeout: float = 5.0,
    include_raw_rdap: bool = False,
) -> CollectedEvidence:
    t = target.strip()
    if not t:
        return CollectedEvidence(
            target=target, input_kind="empty", errors=["empty target"]
        )

    r = dns.resolver.Resolver()
    r.lifetime = dns_timeout
    if dns_timeout and dns_timeout > 0:
        r.timeout = min(float(dns_timeout) / 3.0, 10.0)
    else:
        r.timeout = 5.0

    ev = CollectedEvidence(target=t, input_kind="ip" if _is_ip(t) else "fqdn")
    rdap_to = int(min(max(dns_timeout, 3.0), 60.0))

    try:
        if _is_ip(t):
            ev.derived_ips = [t]
            try:
                ev.fqdn_hints = _unique_preserve_order(
                    [h for h in _dns_ptr(t, r) if h]
                )
            except Exception as e:
                ev.errors.append(f"ptr({t}): {e}")
            netname, emails, asnd, asn, org, raw = _rdap_for_ip(t, timeout=rdap_to)
            if raw and raw.get("error"):
                ev.errors.append(
                    f"rdap({raw.get('ip', t)}): {raw['error']}"
                )
            ev.network_name = netname
            ev.asn_description = asnd
            ev.asn = asn
            ev.organization = org
            ev.network_contact_emails = _unique_preserve_order(emails)
            if include_raw_rdap and raw and isinstance(
                raw, dict
            ) and "error" not in raw:
                ev.raw_rdap = raw
            for hint in list(ev.fqdn_hints):
                try:
                    z = _registered_domain(hint)
                    if z:
                        ev.zone = z
                        ev.nameservers = _unique_preserve_order(
                            _dns_ns_for_domain(z, r) or ev.nameservers
                        )
                except Exception as e:
                    ev.errors.append(f"ns_zone({hint}): {e}")
            return ev

        host = t.rstrip(".")
        ev.fqdn_hints = _unique_preserve_order(
            [host] + (ev.fqdn_hints or [])
        )
        try:
            z = _registered_domain(host)
        except Exception as e:
            ev.errors.append(f"tld({host}): {e}")
            z = None
        ev.zone = z
        try:
            resolved = _dns_lookup_a_aaaa(host, r)
        except Exception as e:
            ev.errors.append(f"dns_A/AAAA({host}): {e}")
            resolved = []
        ev.derived_ips = resolved
        if z:
            try:
                ev.nameservers = _unique_preserve_order(
                    _dns_ns_for_domain(z, r)
                )
            except Exception as e:
                ev.errors.append(f"dns_NS({z}): {e}")
        for ip in list(ev.derived_ips):
            try:
                n, em, d, asn, org, raw = _rdap_for_ip(ip, timeout=rdap_to)
                if raw and raw.get("error"):
                    ev.errors.append(
                        f"rdap({raw.get('ip', ip)}): {raw['error']}"
                    )
                if d and not ev.asn_description:
                    ev.asn_description = d
                if asn and not ev.asn:
                    ev.asn = asn
                if org and not ev.organization:
                    ev.organization = org
                if n and not ev.network_name:
                    ev.network_name = n
                for eml in em:
                    if eml not in ev.network_contact_emails:
                        ev.network_contact_emails.append(eml)
                if include_raw_rdap and not ev.raw_rdap and raw and isinstance(
                    raw, dict
                ) and "error" not in raw:
                    ev.raw_rdap = raw
                for ptr in _dns_ptr(ip, r):
                    if ptr not in ev.fqdn_hints:
                        ev.fqdn_hints.append(ptr)
            except Exception as e:
                ev.errors.append(f"enrich({ip}): {e}")
        if ev.network_contact_emails:
            ev.network_contact_emails = _unique_preserve_order(
                [x.lower() for x in ev.network_contact_emails]
            )
        if ev.derived_ips:
            ev.derived_ips = _unique_preserve_order(ev.derived_ips)
    except Exception as e:
        ev.errors.append(f"collect: {e}")
    return ev


SIGNAL_LABELS = (
    "ip",
    "fqdn",
    "network_name",
    "network_contact_email",
    "ns",
    "asn",
    "asname",
    "org",
)


def _per_signal_match(
    eng: Any,
    find_kwargs: Dict[str, Any],
) -> Dict[str, Optional[Dict[str, Any]]]:
    out: Dict[str, Optional[Dict[str, Any]]] = {}
    keys = {
        "ip": ("ip", "ips"),
        "fqdn": ("fqdn", "fqdns"),
        "network_name": ("network_name",),
        "network_contact_email": (
            "network_contact_email",
            "network_contact_emails",
        ),
        "ns": ("ns_server", "ns_servers"),
        "asn": ("asn", "asns"),
        "asname": ("asname", "asnames"),
        "org": ("organization", "organizations"),
    }
    for label, pkeys in keys.items():
        part: Dict[str, Any] = {}
        for k in pkeys:
            if k in find_kwargs and find_kwargs[k] is not None:
                v = find_kwargs[k]
                if v in ((), [], ""):
                    continue
                part[k] = v
        if not part:
            out[label] = None
            continue
        try:
            out[label] = eng.find(**part)
        except Exception:
            out[label] = None
    return out


def resolve_and_find(
    eng: Any,
    target: str,
    *,
    dns_timeout: float = 5.0,
    min_agreeing_signals: int = 2,
    require_verified: bool = False,
) -> Optional[Dict[str, Any]]:
    try:
        ev = collect_evidence(target, dns_timeout=dns_timeout)
    except Exception as e:
        ev = CollectedEvidence(
            target=target.strip(),
            input_kind="error",
            errors=[f"collect: {e}"],
        )
    fk = ev.to_find_kwargs()
    if not any(
        fk.get(x)
        for x in (
            "ip",
            "ips",
            "fqdn",
            "fqdns",
            "network_name",
            "network_contact_email",
            "network_contact_emails",
            "ns_server",
            "ns_servers",
            "asn",
            "asns",
            "asname",
            "asnames",
            "organization",
            "organizations",
        )
    ):
        return {
            "provider": None,
            "confidence": 0,
            "evidence": ev,
            "per_signal": {},
            "agreement": 0,
            "verified": False,
            "errors": ev.errors,
        }

    try:
        combined = eng.find(**fk)
    except Exception:
        combined = None
    per = _per_signal_match(eng, fk)
    winner = combined.get("provider") if combined else None
    agreed = 0
    for lab in SIGNAL_LABELS:
        p = per.get(lab)
        if (
            p
            and p.get("confidence", 0) > 0
            and winner
            and p.get("provider") == winner
        ):
            agreed += 1
    verified = agreed >= min_agreeing_signals and winner is not None
    if require_verified and not verified:
        return {
            "provider": None,
            "confidence": combined.get("confidence", 0) if combined else 0,
            "evidence": ev,
            "per_signal": per,
            "agreement": agreed,
            "verified": False,
            "errors": ev.errors,
        }
    if not combined:
        return {
            "provider": None,
            "confidence": 0,
            "evidence": ev,
            "per_signal": per,
            "agreement": agreed,
            "verified": False,
            "errors": ev.errors,
        }
    return {
        "provider": combined["provider"],
        "confidence": combined["confidence"],
        "evidence": ev,
        "per_signal": per,
        "agreement": agreed,
        "verified": verified,
        "errors": ev.errors,
    }

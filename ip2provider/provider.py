import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _norm_asn(s: str) -> str:
    t = str(s).upper().replace("AS", "").strip()
    return t if t.isdigit() else ""


class ProviderMatcher:
    def __init__(self, name: str, checks: Dict[str, Dict[str, int]]):
        self.name = name
        self.netname_checks: List[Dict[str, Any]] = []
        self.ptr_checks: List[Dict[str, Any]] = []
        self.netmail_checks: List[Dict[str, Any]] = []
        self.ip_checks: List[Dict[str, Any]] = []
        self.ns_checks: List[Dict[str, Any]] = []
        self.asn_checks: List[Dict[str, Any]] = []
        self.asname_checks: List[Dict[str, Any]] = []
        self.org_checks: List[Dict[str, Any]] = []

        for check_type, patterns in checks.items():
            if check_type == "netname":
                for pattern, confidence in patterns.items():
                    self.netname_checks.append(
                        {
                            "re": re.compile(pattern, re.I),
                            "confidence": confidence,
                        }
                    )
            elif check_type == "ptr":
                for pattern, confidence in patterns.items():
                    self.ptr_checks.append(
                        {
                            "re": re.compile(pattern, re.I),
                            "confidence": confidence,
                        }
                    )
            elif check_type == "ip":
                for ip_addr, confidence in patterns.items():
                    self.ip_checks.append(
                        {
                            "address": ip_addr,
                            "confidence": confidence,
                        }
                    )
            elif check_type == "netmail":
                for pattern, confidence in patterns.items():
                    self.netmail_checks.append(
                        {
                            "re": re.compile(pattern, re.I),
                            "confidence": confidence,
                        }
                    )
            elif check_type == "ns":
                for pattern, confidence in patterns.items():
                    self.ns_checks.append(
                        {
                            "re": re.compile(pattern, re.I),
                            "confidence": confidence,
                        }
                    )
            elif check_type == "asn":
                for k, confidence in patterns.items():
                    a = _norm_asn(k)
                    if a:
                        self.asn_checks.append(
                            {
                                "asn": a,
                                "confidence": confidence,
                            }
                        )
            elif check_type == "asname":
                for pattern, confidence in patterns.items():
                    self.asname_checks.append(
                        {
                            "re": re.compile(pattern, re.I),
                            "confidence": confidence,
                        }
                    )
            elif check_type == "org":
                for pattern, confidence in patterns.items():
                    self.org_checks.append(
                        {
                            "re": re.compile(pattern, re.I),
                            "confidence": confidence,
                        }
                    )

    def calculate_confidence(
        self,
        ip: Optional[str] = None,
        ips: Optional[Sequence[str]] = None,
        fqdn: Optional[str] = None,
        fqdns: Optional[Sequence[str]] = None,
        network_name: Optional[str] = None,
        network_contact_email: Optional[str] = None,
        network_contact_emails: Optional[Sequence[str]] = None,
        ns_server: Optional[str] = None,
        ns_servers: Optional[Sequence[str]] = None,
        asn: Optional[str] = None,
        asns: Optional[Sequence[str]] = None,
        asname: Optional[str] = None,
        asnames: Optional[Sequence[str]] = None,
        organization: Optional[str] = None,
        organizations: Optional[Sequence[str]] = None,
    ) -> int:
        confidence = 0

        if network_name:
            for check in self.netname_checks:
                if check["re"].search(network_name):
                    confidence += check["confidence"]

        email_list: List[str] = []
        if network_contact_emails:
            email_list.extend(str(x) for x in network_contact_emails)
        if network_contact_email and network_contact_email not in email_list:
            email_list.append(network_contact_email)
        if email_list:
            for check in self.netmail_checks:
                for em in email_list:
                    if check["re"].search(em):
                        confidence += check["confidence"]
                        break

        name_list: List[str] = []
        if fqdns:
            name_list.extend(str(x) for x in fqdns)
        if fqdn and fqdn not in name_list:
            name_list.append(fqdn)
        if name_list:
            for check in self.ptr_checks:
                for h in name_list:
                    if check["re"].search(h):
                        confidence += check["confidence"]
                        break

        addr_list: List[str] = []
        if ips:
            addr_list.extend(str(x) for x in ips)
        if ip and ip not in addr_list:
            addr_list.append(ip)
        if addr_list:
            for check in self.ip_checks:
                for a in addr_list:
                    if check["address"] == a:
                        confidence += check["confidence"]
                        break

        ns_list: List[str] = []
        if ns_servers:
            ns_list.extend(str(x) for x in ns_servers)
        if ns_server and ns_server not in ns_list:
            ns_list.append(ns_server)
        if ns_list:
            for check in self.ns_checks:
                for ns in ns_list:
                    if check["re"].search(ns):
                        confidence += check["confidence"]
                        break

        asn_ids: List[str] = []
        if asns:
            asn_ids.extend(_norm_asn(str(x)) for x in asns)
            asn_ids = [x for x in asn_ids if x]
        if asn:
            a = _norm_asn(asn)
            if a and a not in asn_ids:
                asn_ids.append(a)
        if asn_ids:
            for check in self.asn_checks:
                for a in asn_ids:
                    if check["asn"] == a:
                        confidence += check["confidence"]
                        break

        an_list: List[str] = []
        if asnames:
            an_list.extend(str(x) for x in asnames)
        if asname and asname not in an_list:
            an_list.append(asname)
        if an_list:
            for check in self.asname_checks:
                for t in an_list:
                    if check["re"].search(t):
                        confidence += check["confidence"]
                        break

        org_list: List[str] = []
        if organizations:
            org_list.extend(str(x) for x in organizations)
        if organization and organization not in org_list:
            org_list.append(organization)
        if org_list:
            for check in self.org_checks:
                for t in org_list:
                    if check["re"].search(t):
                        confidence += check["confidence"]
                        break

        return confidence


def _load_matchers_v1(rules_data: dict) -> List[ProviderMatcher]:
    if rules_data.get("version") != 1:
        raise ValueError("provider.json: expected version: 1")
    providers = rules_data.get("providers")
    if not isinstance(providers, list) or not providers:
        raise ValueError("provider.json: 'providers' must be a non-empty list")
    matchers: List[ProviderMatcher] = []
    for i, entry in enumerate(providers):
        if not isinstance(entry, dict):
            raise ValueError(f"provider.json: providers[{i}] must be an object")
        name = entry.get("name")
        signals = entry.get("signals")
        if not name or not isinstance(name, str):
            raise ValueError(f"provider.json: providers[{i}].name is required")
        if not isinstance(signals, dict):
            raise ValueError(
                f"provider.json: providers[{i}].signals must be an object"
            )
        matchers.append(ProviderMatcher(name, signals))
    return matchers


class IP2Provider:
    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            rules_path = Path(__file__).parent / "data" / "provider.json"
        else:
            rules_path = Path(rules_path)

        with open(rules_path, "r", encoding="utf-8") as f:
            rules_data = json.load(f)

        self.matchers = _load_matchers_v1(rules_data)

    def find(
        self,
        ip: Optional[str] = None,
        ips: Optional[Sequence[str]] = None,
        fqdn: Optional[str] = None,
        fqdns: Optional[Sequence[str]] = None,
        network_name: Optional[str] = None,
        network_contact_email: Optional[str] = None,
        network_contact_emails: Optional[Sequence[str]] = None,
        ns_server: Optional[str] = None,
        ns_servers: Optional[Sequence[str]] = None,
        asn: Optional[str] = None,
        asns: Optional[Sequence[str]] = None,
        asname: Optional[str] = None,
        asnames: Optional[Sequence[str]] = None,
        organization: Optional[str] = None,
        organizations: Optional[Sequence[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not any(
            [
                ip,
                ips,
                fqdn,
                fqdns,
                network_name,
                network_contact_email,
                network_contact_emails,
                ns_server,
                ns_servers,
                asn,
                asns,
                asname,
                asnames,
                organization,
                organizations,
            ]
        ):
            return None

        confidences: List[Tuple[str, int]] = []
        for matcher in self.matchers:
            confidence = matcher.calculate_confidence(
                ip=ip,
                ips=ips,
                fqdn=fqdn,
                fqdns=fqdns,
                network_name=network_name,
                network_contact_email=network_contact_email,
                network_contact_emails=network_contact_emails,
                ns_server=ns_server,
                ns_servers=ns_servers,
                asn=asn,
                asns=asns,
                asname=asname,
                asnames=asnames,
                organization=organization,
                organizations=organizations,
            )
            confidences.append((matcher.name, confidence))

        max_confidence = max(confidences, key=lambda x: x[1])

        if max_confidence[1] > 0:
            return {
                "provider": max_confidence[0],
                "confidence": max_confidence[1],
            }

        return None

    def resolve_and_find(
        self,
        target: str,
        *,
        dns_timeout: float = 5.0,
        min_agreeing_signals: int = 2,
        require_verified: bool = False,
    ) -> Optional[Dict[str, Any]]:
        from .resolve import resolve_and_find

        return resolve_and_find(
            self,
            target,
            dns_timeout=dns_timeout,
            min_agreeing_signals=min_agreeing_signals,
            require_verified=require_verified,
        )

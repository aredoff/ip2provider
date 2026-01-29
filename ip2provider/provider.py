import json
import re
from pathlib import Path
from typing import Optional, Dict, Any


class ProviderMatcher:
    def __init__(self, name: str, checks: Dict[str, Dict[str, int]]):
        self.name = name
        self.network_checks = []
        self.server_checks = []
        self.ip_checks = []
        self.ns_checks = []
        self.network_contact_email_checks = []

        for check_type, patterns in checks.items():
            if check_type == 'network':
                for pattern, confidence in patterns.items():
                    self.network_checks.append({
                        're': re.compile(pattern, re.I),
                        'confidence': confidence
                    })
            elif check_type == 'server':
                for pattern, confidence in patterns.items():
                    self.server_checks.append({
                        're': re.compile(pattern, re.I),
                        'confidence': confidence
                    })
            elif check_type == 'ip':
                for ip_addr, confidence in patterns.items():
                    self.ip_checks.append({
                        'address': ip_addr,
                        'confidence': confidence
                    })
            elif check_type == 'network_contact_email':
                for pattern, confidence in patterns.items():
                    self.network_contact_email_checks.append({
                        're': re.compile(pattern, re.I),
                        'confidence': confidence
                    })
            elif check_type == 'ns':
                for pattern, confidence in patterns.items():
                    self.ns_checks.append({
                        're': re.compile(pattern, re.I),
                        'confidence': confidence
                    })

    def calculate_confidence(
        self,
        ip: Optional[str] = None,
        fqdn: Optional[str] = None,
        network_name: Optional[str] = None,
        network_contact_email: Optional[str] = None,
        ns_server: Optional[str] = None
    ) -> int:
        confidence = 0

        if network_name:
            for check in self.network_checks:
                if check['re'].search(network_name):
                    confidence += check['confidence']

        if network_contact_email:
            for check in self.network_contact_email_checks:
                if check['re'].search(network_contact_email):
                    confidence += check['confidence']

        if fqdn:
            for check in self.server_checks:
                if check['re'].search(fqdn):
                    confidence += check['confidence']

        if ip:
            for check in self.ip_checks:
                if check['address'] == ip:
                    confidence += check['confidence']

        if ns_server:
            for check in self.ns_checks:
                if check['re'].search(ns_server):
                    confidence += check['confidence']

        return confidence


class IP2Provider:
    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            rules_path = Path(__file__).parent / 'data' / 'hostings.json'
        else:
            rules_path = Path(rules_path)

        with open(rules_path, 'r', encoding='utf-8') as f:
            hostings_data = json.load(f)

        self.matchers = [
            ProviderMatcher(name, checks)
            for name, checks in hostings_data.items()
        ]

    def find(
        self,
        ip: Optional[str] = None,
        fqdn: Optional[str] = None,
        network_name: Optional[str] = None,
        network_contact_email: Optional[str] = None,
        ns_server: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        if not any([ip, fqdn, network_name, network_contact_email, ns_server]):
            return None

        confidences = []
        for matcher in self.matchers:
            confidence = matcher.calculate_confidence(
                ip=ip,
                fqdn=fqdn,
                network_name=network_name,
                network_contact_email=network_contact_email,
                ns_server=ns_server
            )
            confidences.append((matcher.name, confidence))

        max_confidence = max(confidences, key=lambda x: x[1])

        if max_confidence[1] > 0:
            return {
                'provider': max_confidence[0],
                'confidence': max_confidence[1]
            }

        return None

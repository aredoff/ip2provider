from unittest.mock import patch

import pytest

from ip2provider import IP2Provider, collect_evidence, resolve_and_find


@pytest.fixture
def provider():
    return IP2Provider()


def test_collect_evidence_ip_mocked():
    with patch("ip2provider.resolve._rdap_for_ip") as rdap, patch(
        "ip2provider.resolve._dns_ptr"
    ) as ptr, patch("ip2provider.resolve._dns_ns_for_domain") as ns, patch(
        "ip2provider.resolve._registered_domain"
    ) as reg:
        rdap.return_value = (
            "HETZNER",
            ["abuse@hetzner.com"],
            "AS123 Hetzner",
            "24940",
            "Hetzner Org",
            {"ok": True},
        )
        ptr.return_value = ["ptr.example.com"]
        reg.return_value = "example.com"
        ns.return_value = ["ns.hetzner.com"]
        ev = collect_evidence("1.1.1.1")
        assert "1.1.1.1" in ev.derived_ips
        assert ev.network_name == "HETZNER"
        assert "abuse@hetzner.com" in ev.network_contact_emails
        fk = ev.to_find_kwargs()
        assert fk.get("network_name") == "HETZNER"


def test_resolve_and_find_uses_combined(provider):
    with patch("ip2provider.resolve.collect_evidence") as ce:
        evm = ce.return_value
        evm.to_find_kwargs = lambda: {
            "ip": "185.183.122.14",
            "fqdn": "x.tilda.cc",
            "network_name": "TILDA",
            "network_contact_email": "a@tilda.cc",
            "ns_server": "ns1.tilda.cc",
        }
        evm.errors = []
        r = resolve_and_find(provider, "example.com", dns_timeout=1.0)
        assert r is not None
        assert "provider" in r
        assert "per_signal" in r
        assert "agreement" in r


def test_find_lists_ns(provider):
    r = provider.find(
        ns_servers=["ns.hetzner.com", "ns2.hetzner.com"],
    )
    assert r is not None

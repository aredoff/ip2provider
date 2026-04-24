import json
from pathlib import Path

import pytest
from ip2provider import IP2Provider


@pytest.fixture
def provider():
    return IP2Provider()


def test_find_by_network_name(provider):
    result = provider.find(network_name="HETZNER")
    assert result is not None
    assert result["provider"] == "hetzner.com"
    assert result["confidence"] > 0


def test_find_by_fqdn(provider):
    result = provider.find(fqdn="server.hosterby.com")
    assert result is not None
    assert result["provider"] == "hoster.by"


def test_find_by_email(provider):
    result = provider.find(network_contact_email="abuse@hetzner.com")
    assert result is not None
    assert result["provider"] == "hetzner.com"


def test_find_by_multiple_params(provider):
    result = provider.find(
        fqdn="server.hosterby.com",
        network_name="HOSTERBY",
    )
    assert result is not None
    assert result["confidence"] > 100


def test_find_no_match(provider):
    result = provider.find(ip="999.999.999.999")
    assert result is None


def test_find_no_params(provider):
    result = provider.find()
    assert result is None


def test_find_by_ns_server(provider):
    result = provider.find(ns_server="ns.hetzner.com")
    assert result is not None
    assert "provider" in result


def test_find_by_asn_and_asname(tmp_path):
    rules = tmp_path / "r.json"
    rules.write_text(
        """
{
  "version": 1,
  "providers": [
    {
      "name": "acme.host",
      "signals": {
        "asn": { "24940": 100 },
        "asname": { "HETZNER-AS": 50 }
      }
    }
  ]
}
"""
    )
    p = IP2Provider(rules_path=str(rules))
    assert p.find(asn="24940") == {"provider": "acme.host", "confidence": 100}
    assert p.find(asname="HETZNER-AS, DE") == {
        "provider": "acme.host",
        "confidence": 50,
    }


def test_custom_rules(tmp_path):
    rules_file = tmp_path / "custom.json"
    rules_file.write_text(
        """
{
  "version": 1,
  "providers": [
    {
      "name": "test_provider",
      "signals": {
        "netname": { "TEST-NET": 100 }
      }
    }
  ]
}
"""
    )

    prov = IP2Provider(rules_path=str(rules_file))
    result = prov.find(network_name="TEST-NET")
    assert result is not None
    assert result["provider"] == "test_provider"


def test_provider_json_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    data_dir = Path(__file__).resolve().parents[1] / "ip2provider" / "data"
    schema = json.loads(
        (data_dir / "provider.v1.schema.json").read_text(encoding="utf-8")
    )
    data = json.loads(
        (data_dir / "provider.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(
        instance=data, schema=schema, format_checker=jsonschema.FormatChecker()
    )

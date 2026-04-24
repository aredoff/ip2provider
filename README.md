# IP2Provider

Python library to guess a **hosting provider id** from hints you already have (IP, hostname, RDAP-style network fields, DNS) or from a **target string** after live resolution (DNS + RDAP).

## Installation

```bash
pip install ip2provider
```

Runtime dependencies: `dnspython`, `ipwhois`, `tldextract` (see `pyproject.toml`).

## Matching API (`find`)

Load rules (default: bundled `ip2provider/data/provider.json`), then score every known provider and return the one with **highest total confidence** (sum of matching rule weights).

```python
from ip2provider import IP2Provider

provider = IP2Provider()

result = provider.find(
    ip="192.168.1.1",
    fqdn="server.example.com",
    network_name="EXAMPLE-NET",
    network_contact_email="abuse@example.com",
    ns_server="ns1.example.com",
    asn="24940",
    asname="SOME-AS, US",
    organization="Example Org",
)

if result:
    print(result["provider"], result["confidence"])
```

All arguments are optional; pass any subset. Plural forms (`ips`, `fqdns`, `network_contact_emails`, `ns_servers`, `asns`, `asnames`, `organizations`) let you pass several values; the matcher stops after the first hit per rule group where that is defined.

**Inputs and rule types in `provider.json`:**

| `find(...)` argument(s) | Signal key in rules | Match style |
|-------------------------|---------------------|-------------|
| `network_name` | `netname` | regex on netname (RDAP/WHOIS) |
| `fqdn`, `fqdns` | `ptr` | regex on host / PTR name |
| `network_contact_email(s)` | `netmail` | regex on e-mail(s) from RDAP |
| `ip`, `ips` | `ip` | exact string |
| `ns_server`, `ns_servers` | `ns` | regex on NS hostnames |
| `asn`, `asns` | `asn` | exact **numeric AS** (JSON keys are digit strings, e.g. `"24940"`) |
| `asname`, `asnames` | `asname` | regex on AS description (same idea as `asn_description` in RDAP) |
| `organization(s)` | `org` | regex on organisation string from RDAP |

## Resolution API (`collect_evidence`, `resolve_and_find`)

For a user-supplied **IP or hostname**, the library can gather evidence (PTR, A/AAAA, NS, RDAP: netname, e-mails, ASN, AS name, org) and then call `find` with the right kwargs.

```python
from ip2provider import IP2Provider, collect_evidence, resolve_and_find

prov = IP2Provider()
ev = collect_evidence("8.8.8.8", dns_timeout=5.0)
print(ev.to_find_kwargs())

out = resolve_and_find(
    prov,
    "example.com",
    dns_timeout=5.0,
    min_agreeing_signals=2,
    require_verified=False,
)
# out: provider, confidence, evidence, per_signal, agreement, verified, errors
```

`resolve_and_find` returns how many **signal groups** (ip, fqdn, network name, e-mail, ns, asn, asname, org) agree on the winning provider, so you can require multiple independent matches.

## Custom rules file

```python
IP2Provider(rules_path="/path/to/provider.json")
```

The file must be **v1** JSON:

- `version` must be `1`.
- `providers` is a non-empty array; each item has `name` (id returned as `result["provider"]`) and `signals` (a map of signal name → map of `pattern` → **integer weight**).

Regex signals use Python `re` with `re.IGNORECASE`. Exact maps are used for `ip` and `asn` (only digit keys for `asn`).

Example (abbreviated):

```json
{
  "version": 1,
  "providers": [
    {
      "name": "example.com",
      "signals": {
        "netname": { ".*EXAMPLE.*": 100 },
        "ptr": { ".*\\.example\\.com$": 100 },
        "netmail": { "@example.com": 40 },
        "ns": { ".*ns\\.example\\..*": 30 },
        "asn": { "12345": 50 },
        "asname": { ".*EXAMPLE-AS.*": 40 },
        "org": { ".*Example Inc.*": 20 }
      }
    }
  ]
}
```

Optional: set `"$schema": "./provider.v1.schema.json"` next to a copy of [ip2provider/data/provider.v1.schema.json](ip2provider/data/provider.v1.schema.json) for editor validation.

A one-off migrator for the old root-object format lives at `scripts/migrate_provider_json_v1.py`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

`jsonschema` (dev) validates the bundled `provider.json` against `provider.v1.schema.json` in tests.

## License

MIT

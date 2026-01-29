# IP2Provider

Python library to detect hosting provider based on IP, FQDN and network information.

## Installation

```bash
pip install ip2provider
```

## Usage

```python
from ip2provider import IP2Provider

provider = IP2Provider()

result = provider.find(
    ip="192.168.1.1",
    fqdn="server.hosterby.com",
    network_name="HETZNER",
    network_contact_email="abuse@hetzner.com",
    ns_server="ns1.example.com"
)

if result:
    print(f"Provider: {result['provider']}, Confidence: {result['confidence']}")
```

All parameters are optional, you can pass any combination.

## Custom Rules

```python
provider = IP2Provider(rules_path="/path/to/hostings.json")
```

## License

MIT

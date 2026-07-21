from src.cloudflare import build_dns_plan, sync_dns_records


class FakeResponse:
    def __init__(self, result, status_code=200):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._result = result

    def json(self):
        return {"success": self.ok, "result": self._result, "errors": []}


class FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "GET":
            return FakeResponse([])
        payload = kwargs["json"]
        return FakeResponse({"id": f"record-{payload['type'].lower()}", **payload})


def _values():
    return {
        "zone_id": "0123456789abcdef0123456789abcdef",
        "hostname": "proxy.example.com",
        "public_domain": "proxy.example.com",
        "public_ipv4": "203.0.113.10",
        "public_ipv6": "2001:db8::10",
        "cloudflare_proxied": True,
        "api_token": "one-shot-secret-token",
        "ttl": 300,
    }


def test_dns_plan_contains_a_and_aaaa_records():
    plan, errors = build_dns_plan(_values())
    assert errors == []
    assert plan["ttl"] == 1
    assert [record["type"] for record in plan["records"]] == ["A", "AAAA"]


def test_dns_sync_is_explicit_and_does_not_return_token():
    session = FakeSession()
    result = sync_dns_records(_values(), session=session)
    assert [item["action"] for item in result["results"]] == ["created", "created"]
    assert "one-shot-secret-token" not in str(result)
    assert all(
        call[2]["headers"]["Authorization"] == "Bearer one-shot-secret-token"
        for call in session.calls
    )

from datetime import datetime, timezone

from data.advisories.osv_advisory_repository import OsvAdvisoryRepository
from domain.entities.severity import Severity
from tests.data.fake_json_http_client import FakeJsonHttpClient

BASE = "https://api.osv.dev"


def vuln(vuln_id="GHSA-1", **extra):
    body = {
        "id": vuln_id,
        "aliases": ["CVE-2024-1"],
        "summary": "bad",
        "published": "2024-01-02T03:04:05Z",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "pkg", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            },
            {
                "package": {"name": "other", "ecosystem": "npm"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            },
        ],
    }
    body.update(extra)
    return body


def make(get_responses, post_handler):
    return FakeJsonHttpClient(get_responses, post_handler)


def test_prefetch_then_find_uses_cache_and_converts():
    def handler(url, payload):
        assert url == f"{BASE}/v1/querybatch"
        return {"results": [{"vulns": [{"id": "GHSA-1"}]} for _ in payload["queries"]]}

    client = make({f"{BASE}/v1/vulns/GHSA-1": vuln()}, handler)
    repository = OsvAdvisoryRepository(client)
    repository.prefetch([("npm", "pkg", "1.0.0"), ("npm", "pkg", "1.1.0")])
    advisories = repository.find_advisories("npm", "pkg", "1.0.0")
    repository.find_advisories("npm", "pkg", "1.1.0")
    advisory = advisories[0]
    assert advisory.published_at == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert advisory.severity == Severity.HIGH
    assert advisory.fixed_versions == ("1.2.3",)
    assert advisory.aliases == ("CVE-2024-1",)
    assert len(client.post_calls) == 1
    assert client.get_calls == [f"{BASE}/v1/vulns/GHSA-1"]
    assert client.post_calls[0][1]["queries"][0] == {
        "package": {"name": "pkg", "ecosystem": "npm"},
        "version": "1.0.0",
    }


def test_prefetch_batches_of_1000():
    def handler(url, payload):
        return {"results": [{} for _ in payload["queries"]]}

    client = make({}, handler)
    queries = [("npm", f"p{i}", "1.0.0") for i in range(1001)]
    OsvAdvisoryRepository(client).prefetch(queries)
    assert [len(c[1]["queries"]) for c in client.post_calls] == [1000, 1]


def test_pagination_repeats_only_paginated_queries():
    def handler(url, payload):
        queries = payload["queries"]
        if "page_token" not in queries[0] and len(queries) == 2:
            return {
                "results": [
                    {"vulns": [{"id": "A"}], "next_page_token": "t"},
                    {"vulns": [{"id": "B"}]},
                ]
            }
        assert len(queries) == 1 and queries[0]["page_token"] == "t"
        return {"results": [{"vulns": [{"id": "C"}]}]}

    responses = {f"{BASE}/v1/vulns/{i}": vuln(i) for i in "ABC"}
    repository = OsvAdvisoryRepository(make(responses, handler))
    repository.prefetch([("npm", "pkg", "1"), ("npm", "pkg", "2")])
    ids = [a.advisory_id for a in repository.find_advisories("npm", "pkg", "1")]
    assert ids == ["A", "C"]


def test_find_without_prefetch_queries_single():
    def handler(url, payload):
        assert url == f"{BASE}/v1/query"
        return {"vulns": [{"id": "GHSA-1"}]}

    client = make({f"{BASE}/v1/vulns/GHSA-1": vuln()}, handler)
    repository = OsvAdvisoryRepository(client)
    assert len(repository.find_advisories("npm", "pkg", "1.0.0")) == 1
    repository.find_advisories("npm", "pkg", "1.0.0")
    assert len(client.post_calls) == 1


def advisory_for(body):
    handler = lambda url, payload: {"vulns": [{"id": body["id"]}]}
    client = make({f"{BASE}/v1/vulns/{body['id']}": body}, handler)
    return OsvAdvisoryRepository(client).find_advisories("npm", "pkg", "1")[0]


def test_severity_fallbacks():
    base = vuln(database_specific={})
    base["affected"][0]["ecosystem_specific"] = {"severity": "moderate"}
    assert advisory_for(base).severity == Severity.MEDIUM
    scored = vuln(database_specific={}, severity=[{"type": "CVSS_V3", "score": "9.8"}])
    assert advisory_for(scored).severity == Severity.CRITICAL
    vector = vuln(database_specific={}, severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}])
    assert advisory_for(vector).severity == Severity.UNKNOWN


def test_summary_falls_back_to_truncated_details():
    body = vuln(summary=None, details="x" * 500)
    assert advisory_for(body).summary == "x" * 200

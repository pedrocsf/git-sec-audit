from datetime import datetime, timezone

from data.advisories.ecosystem_release_router import EcosystemReleaseRouter
from data.advisories.npm_registry_release_repository import NpmRegistryReleaseRepository
from data.advisories.pub_dev_release_repository import PubDevReleaseRepository
from tests.data.fake_json_http_client import FakeJsonHttpClient


def test_pub_dev_lists_sorted_and_caches():
    url = "https://pub.dev/api/packages/http"
    client = FakeJsonHttpClient(
        {
            url: {
                "versions": [
                    {"version": "2.0.0", "published": "2024-02-01T00:00:00.000000Z"},
                    {"version": "1.0.0", "published": "2023-01-01T00:00:00.000000Z"},
                ]
            }
        }
    )
    repository = PubDevReleaseRepository(client)
    releases = repository.list_releases("Pub", "http")
    assert [r.version for r in releases] == ["1.0.0", "2.0.0"]
    assert releases[0].released_at == datetime(2023, 1, 1, tzinfo=timezone.utc)
    assert repository.find_release("Pub", "http", "2.0.0").version == "2.0.0"
    assert repository.find_release("Pub", "http", "3.0.0") is None
    assert client.get_calls == [url]


def test_pub_dev_404_returns_empty():
    repository = PubDevReleaseRepository(FakeJsonHttpClient())
    assert repository.list_releases("Pub", "missing") == []


def test_npm_ignores_created_modified_and_encodes_scope():
    url = "https://registry.npmjs.org/@scope%2Fname"
    client = FakeJsonHttpClient(
        {
            url: {
                "time": {
                    "created": "2020-01-01T00:00:00.000Z",
                    "modified": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2021-01-01T00:00:00.000Z",
                    "1.0.0": "2020-06-01T00:00:00.000Z",
                }
            }
        }
    )
    repository = NpmRegistryReleaseRepository(client)
    releases = repository.list_releases("npm", "@scope/name")
    assert [r.version for r in releases] == ["1.0.0", "1.1.0"]
    assert client.get_calls == [url]


def test_npm_404_returns_empty():
    assert NpmRegistryReleaseRepository(FakeJsonHttpClient()).list_releases("npm", "x") == []


def test_router_delegates_and_handles_unknown():
    url = "https://pub.dev/api/packages/http"
    client = FakeJsonHttpClient(
        {url: {"versions": [{"version": "1.0.0", "published": "2023-01-01T00:00:00Z"}]}}
    )
    router = EcosystemReleaseRouter({"Pub": PubDevReleaseRepository(client)})
    assert len(router.list_releases("Pub", "http")) == 1
    assert router.find_release("Pub", "http", "1.0.0") is not None
    assert router.list_releases("Go", "x") == []
    assert router.find_release("Go", "x", "1") is None

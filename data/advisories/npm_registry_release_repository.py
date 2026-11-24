from urllib.parse import quote

from data.advisories.pub_dev_release_repository import parse_utc
from data.http.json_http_client import JsonHttpClient
from domain.entities.package_release import PackageRelease
from domain.repositories.package_release_repository import PackageReleaseRepository

NPM_REGISTRY_URL = "https://registry.npmjs.org/"
NON_VERSION_TIME_KEYS = ("created", "modified")


class NpmRegistryReleaseRepository(PackageReleaseRepository):
    def __init__(self, http_client: JsonHttpClient) -> None:
        self._http_client = http_client
        self._cache: dict[str, list[PackageRelease]] = {}

    def list_releases(self, ecosystem: str, package: str) -> list[PackageRelease]:
        if package not in self._cache:
            self._cache[package] = self._fetch(ecosystem, package)
        return list(self._cache[package])

    def find_release(
        self, ecosystem: str, package: str, version: str
    ) -> PackageRelease | None:
        for release in self.list_releases(ecosystem, package):
            if release.version == version:
                return release
        return None

    def _fetch(self, ecosystem: str, package: str) -> list[PackageRelease]:
        body = self._http_client.get_json(NPM_REGISTRY_URL + quote(package, safe="@"))
        if body is None:
            return []
        releases = [
            PackageRelease(ecosystem, package, version, parse_utc(published))
            for version, published in body.get("time", {}).items()
            if version not in NON_VERSION_TIME_KEYS
        ]
        return sorted(releases, key=lambda release: release.released_at)

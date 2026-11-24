from datetime import datetime, timezone

from data.http.json_http_client import JsonHttpClient
from domain.entities.package_release import PackageRelease
from domain.repositories.package_release_repository import PackageReleaseRepository

PUB_DEV_PACKAGE_URL = "https://pub.dev/api/packages/{name}"


def parse_utc(text: str) -> datetime:
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class PubDevReleaseRepository(PackageReleaseRepository):
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
        body = self._http_client.get_json(PUB_DEV_PACKAGE_URL.format(name=package))
        if body is None:
            return []
        releases = [
            PackageRelease(ecosystem, package, entry["version"], parse_utc(entry["published"]))
            for entry in body.get("versions", [])
            if entry.get("published")
        ]
        return sorted(releases, key=lambda release: release.released_at)

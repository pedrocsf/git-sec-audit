from domain.repositories.package_release_repository import PackageReleaseRepository


class FakePackageReleaseRepository(PackageReleaseRepository):
    def __init__(self, releases=None):
        self._releases = list(releases or [])

    def list_releases(self, ecosystem, package):
        matching = [
            release
            for release in self._releases
            if release.ecosystem == ecosystem and release.package == package
        ]
        return sorted(matching, key=lambda release: release.released_at)

    def find_release(self, ecosystem, package, version):
        for release in self._releases:
            if (release.ecosystem, release.package, release.version) == (
                ecosystem,
                package,
                version,
            ):
                return release
        return None

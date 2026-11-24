from domain.entities.package_release import PackageRelease
from domain.repositories.package_release_repository import PackageReleaseRepository


class EcosystemReleaseRouter(PackageReleaseRepository):
    def __init__(
        self, repositories_by_ecosystem: dict[str, PackageReleaseRepository]
    ) -> None:
        self._repositories_by_ecosystem = repositories_by_ecosystem

    def list_releases(self, ecosystem: str, package: str) -> list[PackageRelease]:
        repository = self._repositories_by_ecosystem.get(ecosystem)
        if repository is None:
            return []
        return repository.list_releases(ecosystem, package)

    def find_release(
        self, ecosystem: str, package: str, version: str
    ) -> PackageRelease | None:
        repository = self._repositories_by_ecosystem.get(ecosystem)
        if repository is None:
            return None
        return repository.find_release(ecosystem, package, version)

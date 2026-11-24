from abc import ABC, abstractmethod

from domain.entities.package_release import PackageRelease


class PackageReleaseRepository(ABC):
    @abstractmethod
    def list_releases(self, ecosystem: str, package: str) -> list[PackageRelease]:
        ...

    @abstractmethod
    def find_release(
        self, ecosystem: str, package: str, version: str
    ) -> PackageRelease | None:
        ...

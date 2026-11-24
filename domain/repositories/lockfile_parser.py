from abc import ABC, abstractmethod

from domain.entities.dependency_version import LockedPackage


class LockfileParser(ABC):
    @abstractmethod
    def supports(self, path: str) -> bool:
        ...

    @abstractmethod
    def parse(self, content: str) -> list[LockedPackage]:
        ...

from abc import ABC, abstractmethod

from domain.entities.advisory import Advisory


class AdvisoryRepository(ABC):
    @abstractmethod
    def prefetch(self, queries: list[tuple[str, str, str]]) -> None:
        ...

    @abstractmethod
    def find_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> list[Advisory]:
        ...

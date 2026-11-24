from abc import ABC, abstractmethod

from domain.entities.insecure_pattern_finding import BlobToScan, PatternMatch


class PatternScannerRepository(ABC):
    @property
    @abstractmethod
    def scanner_id(self) -> str:
        ...

    @abstractmethod
    def supports(self, path: str) -> bool:
        ...

    @abstractmethod
    def scan_blobs(self, blobs: list[BlobToScan]) -> dict[str, list[PatternMatch]]:
        ...

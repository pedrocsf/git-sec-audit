from abc import ABC, abstractmethod

from domain.entities.secret_finding import SecretFinding


class SecretScannerRepository(ABC):
    @abstractmethod
    def scan_history(self, branch: str) -> list[SecretFinding]:
        ...

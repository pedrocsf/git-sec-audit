from abc import ABC, abstractmethod


class ResourceMonitor(ABC):
    @abstractmethod
    def ensure_capacity(
        self, required_disk_bytes: int, required_memory_bytes: int
    ) -> None:
        ...

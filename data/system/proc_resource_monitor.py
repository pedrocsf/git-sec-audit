import os
import shutil

from domain.errors import InsufficientResourcesError
from domain.repositories.resource_monitor import ResourceMonitor

MEMINFO_PATH = "/proc/meminfo"
MEMORY_AVAILABLE_KEY = "MemAvailable:"
KIBIBYTE = 1024
MEGABYTE = 1024 * 1024
SAFETY_FACTOR = 2
MINIMUM_FREE_INODES = 1000


class ProcResourceMonitor(ResourceMonitor):
    def __init__(self, target_path: str) -> None:
        self._target_path = target_path

    def ensure_capacity(
        self, required_disk_bytes: int, required_memory_bytes: int
    ) -> None:
        free_disk = shutil.disk_usage(self._target_path).free
        needed_disk = required_disk_bytes * SAFETY_FACTOR
        if free_disk < needed_disk:
            raise InsufficientResourcesError(
                f"Insufficient disk space: {free_disk // MEGABYTE} MB free, "
                f"{needed_disk // MEGABYTE} MB required"
            )
        available_memory = self._read_available_memory_bytes()
        needed_memory = required_memory_bytes * SAFETY_FACTOR
        if available_memory < needed_memory:
            raise InsufficientResourcesError(
                f"Insufficient memory: {available_memory // MEGABYTE} MB available, "
                f"{needed_memory // MEGABYTE} MB required"
            )
        free_inodes = os.statvfs(self._target_path).f_favail
        if free_inodes < MINIMUM_FREE_INODES:
            raise InsufficientResourcesError(
                f"Insufficient inodes: {free_inodes} free, "
                f"{MINIMUM_FREE_INODES} required"
            )

    def _read_available_memory_bytes(self) -> int:
        try:
            with open(MEMINFO_PATH, encoding="ascii") as meminfo:
                for line in meminfo:
                    if line.startswith(MEMORY_AVAILABLE_KEY):
                        return int(line.split()[1]) * KIBIBYTE
        except OSError as error:
            raise InsufficientResourcesError(
                f"Unable to read memory information: {error}"
            ) from error
        raise InsufficientResourcesError("MemAvailable not found in /proc/meminfo")

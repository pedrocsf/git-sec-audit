import pytest

from data.system.proc_resource_monitor import ProcResourceMonitor
from domain.errors import InsufficientResourcesError

HUGE = 1 << 60


def test_small_requirements_pass(tmp_path):
    ProcResourceMonitor(str(tmp_path)).ensure_capacity(1024, 1024)


def test_huge_disk_raises_with_megabytes(tmp_path):
    with pytest.raises(InsufficientResourcesError, match="MB"):
        ProcResourceMonitor(str(tmp_path)).ensure_capacity(HUGE, 1024)


def test_huge_memory_raises_with_megabytes(tmp_path):
    with pytest.raises(InsufficientResourcesError, match="memory.*MB"):
        ProcResourceMonitor(str(tmp_path)).ensure_capacity(1024, HUGE)

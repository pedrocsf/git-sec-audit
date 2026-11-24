from domain.repositories.resource_monitor import ResourceMonitor


class FakeResourceMonitor(ResourceMonitor):
    def __init__(self, error=None):
        self.calls = []
        self._error = error

    def ensure_capacity(self, required_disk_bytes, required_memory_bytes):
        self.calls.append((required_disk_bytes, required_memory_bytes))
        if self._error is not None:
            raise self._error

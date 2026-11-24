from domain.repositories.advisory_repository import AdvisoryRepository


class FakeAdvisoryRepository(AdvisoryRepository):
    def __init__(self, advisories=None):
        self._advisories = dict(advisories or {})
        self.prefetched = []

    def prefetch(self, queries):
        self.prefetched.extend(queries)

    def find_advisories(self, ecosystem, package, version):
        return list(self._advisories.get((ecosystem, package, version), []))

from domain.errors import LockfileParseError
from domain.repositories.lockfile_parser import LockfileParser


class FakeLockfileParser(LockfileParser):
    def __init__(self, supported_names=("pubspec.lock",), packages_by_content=None):
        self._supported_names = tuple(supported_names)
        self._packages_by_content = dict(packages_by_content or {})

    def supports(self, path):
        return path.rsplit("/", 1)[-1] in self._supported_names

    def parse(self, content):
        if content not in self._packages_by_content:
            raise LockfileParseError("unparseable content")
        return list(self._packages_by_content[content])

import yaml

from domain.entities.dependency_version import LockedPackage
from domain.entities.ecosystem import PUB_ECOSYSTEM
from domain.errors import LockfileParseError
from domain.repositories.lockfile_parser import LockfileParser

LOCKFILE_NAME = "pubspec.lock"
PACKAGES_KEY = "packages"
SOURCE_KEY = "source"
VERSION_KEY = "version"
HOSTED_SOURCE = "hosted"


class PubspecLockParser(LockfileParser):
    def supports(self, path: str) -> bool:
        return path.replace("\\", "/").rsplit("/", 1)[-1] == LOCKFILE_NAME

    def parse(self, content: str) -> list[LockedPackage]:
        try:
            document = yaml.safe_load(content)
        except yaml.YAMLError as error:
            raise LockfileParseError(f"invalid pubspec.lock: {error}") from error
        if document is None:
            return []
        if not isinstance(document, dict):
            raise LockfileParseError("pubspec.lock root must be a mapping")
        packages = document.get(PACKAGES_KEY)
        if packages is None:
            return []
        if not isinstance(packages, dict):
            raise LockfileParseError("pubspec.lock packages must be a mapping")
        return [
            locked
            for name, entry in packages.items()
            if (locked := self._to_locked_package(name, entry)) is not None
        ]

    def _to_locked_package(self, name: object, entry: object) -> LockedPackage | None:
        if not isinstance(entry, dict):
            raise LockfileParseError(f"unexpected entry for package {name}")
        if entry.get(SOURCE_KEY) != HOSTED_SOURCE:
            return None
        version = entry.get(VERSION_KEY)
        if version is None:
            raise LockfileParseError(f"missing version for package {name}")
        return LockedPackage(PUB_ECOSYSTEM, str(name), str(version))

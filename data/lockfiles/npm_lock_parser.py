import json

from domain.entities.dependency_version import LockedPackage
from domain.entities.ecosystem import NPM_ECOSYSTEM
from domain.errors import LockfileParseError
from domain.repositories.lockfile_parser import LockfileParser

LOCKFILE_NAME = "package-lock.json"
NODE_MODULES_SEGMENT = "node_modules/"
ROOT_PACKAGE_KEY = ""
PACKAGES_KEY = "packages"
DEPENDENCIES_KEY = "dependencies"
LOCKFILE_VERSION_KEY = "lockfileVersion"
LEGACY_LOCKFILE_VERSION = 1
NAME_KEY = "name"
VERSION_KEY = "version"
LINK_KEY = "link"


class NpmLockParser(LockfileParser):
    def supports(self, path: str) -> bool:
        return path.replace("\\", "/").rsplit("/", 1)[-1] == LOCKFILE_NAME

    def parse(self, content: str) -> list[LockedPackage]:
        try:
            document = json.loads(content)
        except json.JSONDecodeError as error:
            raise LockfileParseError(f"invalid package-lock.json: {error}") from error
        if not isinstance(document, dict):
            raise LockfileParseError("package-lock.json root must be an object")
        pairs: dict[tuple[str, str], None] = {}
        if document.get(LOCKFILE_VERSION_KEY) == LEGACY_LOCKFILE_VERSION or (
            PACKAGES_KEY not in document
        ):
            self._collect_legacy(document.get(DEPENDENCIES_KEY), pairs)
        else:
            self._collect_modern(document.get(PACKAGES_KEY), pairs)
        return [LockedPackage(NPM_ECOSYSTEM, name, version) for name, version in pairs]

    def _collect_modern(self, packages: object, pairs: dict) -> None:
        if not isinstance(packages, dict):
            raise LockfileParseError("package-lock.json packages must be an object")
        for key, entry in packages.items():
            if key == ROOT_PACKAGE_KEY or not isinstance(entry, dict):
                continue
            if entry.get(LINK_KEY) is True:
                continue
            version = entry.get(VERSION_KEY)
            if not isinstance(version, str):
                continue
            name = entry.get(NAME_KEY) or key.rsplit(NODE_MODULES_SEGMENT, 1)[-1]
            pairs[(name, version)] = None

    def _collect_legacy(self, dependencies: object, pairs: dict) -> None:
        if dependencies is None:
            return
        if not isinstance(dependencies, dict):
            raise LockfileParseError("package-lock.json dependencies must be an object")
        for name, entry in dependencies.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get(VERSION_KEY)
            if isinstance(version, str):
                pairs[(name, version)] = None
            self._collect_legacy(entry.get(DEPENDENCIES_KEY), pairs)

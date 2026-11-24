import re

import yaml

from domain.entities.dependency_version import LockedPackage
from domain.entities.ecosystem import PUB_ECOSYSTEM
from domain.errors import LockfileParseError
from domain.repositories.lockfile_parser import LockfileParser

MANIFEST_NAME = "pubspec.yaml"
DEPENDENCY_SECTIONS = ("dependencies", "dev_dependencies")
VERSION_KEY = "version"
IGNORED_KEYS = ("sdk", "path", "git")
HOSTED_KEY = "hosted"
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)*(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")


class PubspecYamlParser(LockfileParser):
    def supports(self, path: str) -> bool:
        return path.replace("\\", "/").rsplit("/", 1)[-1] == MANIFEST_NAME

    def parse(self, content: str) -> list[LockedPackage]:
        try:
            document = yaml.safe_load(content)
        except yaml.YAMLError as error:
            raise LockfileParseError(f"invalid pubspec.yaml: {error}") from error
        if document is None:
            return []
        if not isinstance(document, dict):
            raise LockfileParseError("pubspec.yaml root must be a mapping")
        packages: list[LockedPackage] = []
        for section in DEPENDENCY_SECTIONS:
            packages.extend(self._parse_section(document.get(section)))
        return packages

    def _parse_section(self, section: object) -> list[LockedPackage]:
        if section is None:
            return []
        if not isinstance(section, dict):
            raise LockfileParseError("dependencies section must be a mapping")
        packages = []
        for name, spec in section.items():
            version = self._lowest_version(self._constraint_of(spec))
            if version is not None:
                packages.append(
                    LockedPackage(PUB_ECOSYSTEM, str(name), version, approximated=True)
                )
        return packages

    def _constraint_of(self, spec: object) -> str | None:
        if isinstance(spec, str):
            return spec
        if not isinstance(spec, dict):
            return None
        if any(key in spec for key in IGNORED_KEYS):
            return None
        constraint = spec.get(VERSION_KEY)
        return constraint if isinstance(constraint, str) else None

    def _lowest_version(self, constraint: str | None) -> str | None:
        if not constraint:
            return None
        match = VERSION_PATTERN.search(constraint)
        return match.group(0) if match else None

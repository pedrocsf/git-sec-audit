import re
from dataclasses import dataclass
from functools import total_ordering

_PREFIX_PATTERN = re.compile(r"^(?:>=|[v^~=])+")
_VERSION_PATTERN = re.compile(
    r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$"
)
_BUILD_SEPARATOR = "+"
_NUMERIC_RANK = 0
_ALPHANUMERIC_RANK = 1


def _identifier_key(identifier: str) -> tuple[int, int, str]:
    if identifier.isdigit():
        return (_NUMERIC_RANK, int(identifier), "")
    return (_ALPHANUMERIC_RANK, 0, identifier)


@total_ordering
@dataclass(frozen=True)
class SemanticVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @property
    def is_prerelease(self) -> bool:
        return len(self.prerelease) > 0

    def _sort_key(self) -> tuple:
        core = (self.major, self.minor, self.patch)
        if not self.prerelease:
            return (core, 1, ())
        return (core, 0, tuple(_identifier_key(item) for item in self.prerelease))

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._sort_key() < other._sort_key()

    @classmethod
    def parse(cls, text: str) -> "SemanticVersion | None":
        cleaned = _PREFIX_PATTERN.sub("", text.strip())
        cleaned = cleaned.split(_BUILD_SEPARATOR, 1)[0].strip()
        match = _VERSION_PATTERN.match(cleaned)
        if match is None:
            return None
        major, minor, patch, prerelease = match.groups()
        identifiers = tuple(prerelease.split(".")) if prerelease else ()
        if any(identifier == "" for identifier in identifiers):
            return None
        return cls(int(major), int(minor or 0), int(patch or 0), identifiers)

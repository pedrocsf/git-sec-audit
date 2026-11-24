from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LockedPackage:
    ecosystem: str
    name: str
    version: str
    approximated: bool = False


@dataclass(frozen=True)
class DependencyVersion:
    ecosystem: str
    package: str
    version: str
    lockfile_path: str
    start_commit_sha: str
    start_at: datetime
    end_commit_sha: str | None
    end_at: datetime | None
    approximated: bool = False

    @property
    def is_current(self) -> bool:
        return self.end_at is None

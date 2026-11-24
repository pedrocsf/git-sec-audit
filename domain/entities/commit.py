from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from domain.entities.author import Author


class FileChangeStatus(StrEnum):
    ADDED = "A"
    MODIFIED = "M"
    DELETED = "D"
    TYPE_CHANGED = "T"


@dataclass(frozen=True)
class FileChange:
    path: str
    status: FileChangeStatus
    old_blob_sha: str | None
    new_blob_sha: str | None


@dataclass(frozen=True)
class Commit:
    sha: str
    author: Author
    authored_at: datetime
    committed_at: datetime
    parent_shas: tuple[str, ...]
    subject: str
    file_changes: tuple[FileChange, ...] = ()

    @property
    def is_merge(self) -> bool:
        return len(self.parent_shas) > 1

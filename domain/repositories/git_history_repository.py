from abc import ABC, abstractmethod

from domain.entities.author import Author
from domain.entities.commit import Commit


class GitHistoryRepository(ABC):
    @abstractmethod
    def list_commits(
        self, branch: str, first_parent: bool, paths: tuple[str, ...] = ()
    ) -> list[Commit]:
        ...

    @abstractmethod
    def resolve_commit(self, revision: str) -> str:
        ...

    @abstractmethod
    def read_file_at(self, commit_sha: str, path: str) -> str | None:
        ...

    @abstractmethod
    def read_blob(self, blob_sha: str) -> bytes:
        ...

    @abstractmethod
    def find_paths_in_history(
        self, branch: str, file_names: tuple[str, ...]
    ) -> list[str]:
        ...

    @abstractmethod
    def blame_line(
        self, commit_sha: str, path: str, line: int, ignore_revs_file: str | None
    ) -> tuple[str, Author] | None:
        ...

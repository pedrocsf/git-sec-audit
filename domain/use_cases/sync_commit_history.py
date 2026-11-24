from dataclasses import dataclass

from domain.entities.commit import Commit
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.git_history_repository import GitHistoryRepository

REPOSITORY_NAME_KEY = "repository_name"


@dataclass(frozen=True)
class SyncCommitHistoryRequest:
    repository_name: str
    branch: str
    first_parent: bool


class SyncCommitHistory:
    def __init__(
        self,
        git_history_repository: GitHistoryRepository,
        audit_result_repository: AuditResultRepository,
    ) -> None:
        self._git_history_repository = git_history_repository
        self._audit_result_repository = audit_result_repository

    def execute(self, request: SyncCommitHistoryRequest) -> list[Commit]:
        commits = self._git_history_repository.list_commits(
            request.branch, request.first_parent
        )
        self._audit_result_repository.save_commits(commits)
        self._audit_result_repository.save_run_metadata(
            REPOSITORY_NAME_KEY, request.repository_name
        )
        return commits

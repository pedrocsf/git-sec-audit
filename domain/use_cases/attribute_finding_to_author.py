from dataclasses import dataclass, replace

from domain.entities.author import Author
from domain.entities.finding_lifecycle import FindingLifecycle
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.git_history_repository import GitHistoryRepository


@dataclass(frozen=True)
class AttributeFindingToAuthorRequest:
    head_revision: str
    ignore_revs_file: str | None = None


class AttributeFindingToAuthor:
    def __init__(
        self,
        git_history_repository: GitHistoryRepository,
        audit_result_repository: AuditResultRepository,
    ) -> None:
        self._git_history_repository = git_history_repository
        self._audit_result_repository = audit_result_repository

    def execute(self, request: AttributeFindingToAuthorRequest) -> list[FindingLifecycle]:
        authors_by_commit = {
            commit.sha: commit.author
            for commit in self._audit_result_repository.load_commits()
        }
        lifecycles = self._audit_result_repository.load_finding_lifecycles()
        head_sha = self._resolve_head(request, lifecycles)
        attributed = [
            self._attribute(lifecycle, authors_by_commit, head_sha, request)
            for lifecycle in lifecycles
        ]
        self._audit_result_repository.save_finding_lifecycles(attributed)
        return attributed

    def _resolve_head(
        self, request: AttributeFindingToAuthorRequest, lifecycles: list[FindingLifecycle]
    ) -> str | None:
        if not any(lifecycle.is_open for lifecycle in lifecycles):
            return None
        return self._git_history_repository.resolve_commit(request.head_revision)

    def _attribute(
        self,
        lifecycle: FindingLifecycle,
        authors_by_commit: dict[str, Author],
        head_sha: str | None,
        request: AttributeFindingToAuthorRequest,
    ) -> FindingLifecycle:
        introducing_author = authors_by_commit.get(lifecycle.introduced_commit_sha)
        if introducing_author is None:
            introducing_author = lifecycle.introduced_by
        author = introducing_author
        if lifecycle.is_open and head_sha is not None:
            blamed = self._git_history_repository.blame_line(
                head_sha,
                lifecycle.file_path,
                lifecycle.last_seen_line,
                request.ignore_revs_file,
            )
            if blamed is not None:
                author = blamed[1]
        return replace(lifecycle, introduced_by=author)

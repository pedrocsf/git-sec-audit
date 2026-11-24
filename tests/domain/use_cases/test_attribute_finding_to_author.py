from datetime import datetime, timezone

from domain.entities.author import Author
from domain.entities.commit import Commit
from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.severity import Severity
from domain.use_cases.attribute_finding_to_author import (
    AttributeFindingToAuthor,
    AttributeFindingToAuthorRequest,
)
from tests.fakes.fake_git_history_repository import FakeGitHistoryRepository
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository

INTRODUCER = Author("Ana", "ana@x.com")
BLAMED = Author("Bob", "bob@x.com")
HEAD = "head"


def moment(day):
    return datetime(2024, 1, day, tzinfo=timezone.utc)


def lifecycle(fixed):
    return FindingLifecycle(
        "fp", FindingKind.INSECURE_PATTERN, "r", "c", Severity.HIGH, "a.py", "(root)",
        "c1", moment(1), "c2" if fixed else None, moment(2) if fixed else None, 5,
    )


class RecordingGit(FakeGitHistoryRepository):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ignore_files = []

    def blame_line(self, commit_sha, path, line, ignore_revs_file):
        self.ignore_files.append(ignore_revs_file)
        return super().blame_line(commit_sha, path, line, ignore_revs_file)


def run(item, blame, ignore=None):
    repository = InMemoryAuditResultRepository()
    repository.save_commits([Commit("c1", INTRODUCER, moment(1), moment(1), (), "s")])
    repository.save_finding_lifecycles([item])
    git = RecordingGit(blame=blame, head_sha=HEAD)
    use_case = AttributeFindingToAuthor(git, repository)
    result = use_case.execute(AttributeFindingToAuthorRequest("HEAD", ignore))
    assert repository.load_finding_lifecycles() == result
    return result[0], git


def test_closed_uses_introducing_commit_author():
    result, git = run(lifecycle(True), {(HEAD, "a.py", 5): ("x", BLAMED)})
    assert result.introduced_by == INTRODUCER
    assert git.ignore_files == []


def test_open_uses_blame_at_head():
    result, _ = run(lifecycle(False), {(HEAD, "a.py", 5): ("x", BLAMED)})
    assert result.introduced_by == BLAMED


def test_open_without_blame_falls_back_to_introducer():
    result, _ = run(lifecycle(False), {})
    assert result.introduced_by == INTRODUCER


def test_ignore_revs_file_is_forwarded():
    _, git = run(lifecycle(False), {}, ignore="ignore.txt")
    assert git.ignore_files == ["ignore.txt"]

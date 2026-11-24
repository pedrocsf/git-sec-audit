from datetime import datetime, timezone

from domain.entities.author import Author
from domain.entities.commit import Commit
from domain.use_cases.sync_commit_history import SyncCommitHistory, SyncCommitHistoryRequest
from tests.fakes.fake_git_history_repository import FakeGitHistoryRepository
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository


def make_commit(sha):
    moment = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return Commit(sha, Author("Ana", "ana@x.com"), moment, moment, (), "subject")


def test_saves_commits_and_repository_name():
    commits = [make_commit("a"), make_commit("b")]
    results = InMemoryAuditResultRepository()
    use_case = SyncCommitHistory(FakeGitHistoryRepository(commits=commits), results)

    returned = use_case.execute(SyncCommitHistoryRequest("demo", "main", True))

    assert returned == commits
    assert results.load_commits() == commits
    assert results.load_run_metadata("repository_name") == "demo"

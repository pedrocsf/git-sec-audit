import hashlib
from datetime import datetime, timezone

from domain.entities.author import Author
from domain.entities.commit import Commit, FileChange, FileChangeStatus
from domain.entities.finding_lifecycle import FindingKind
from domain.entities.insecure_pattern_finding import InsecurePatternFinding
from domain.entities.secret_finding import SecretFinding
from domain.entities.severity import Severity
from domain.use_cases.track_finding_lifecycle import TrackFindingLifecycle
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository

AUTHOR = Author("Ana", "ana@x.com")
PATH = "lib/a.dart"


def moment(day):
    return datetime(2024, 1, day, tzinfo=timezone.utc)


def commit(sha, day, path=PATH, blob="b", status=FileChangeStatus.MODIFIED):
    change = FileChange(path, status, None, blob)
    return Commit(sha, AUTHOR, moment(day), moment(day), (), "s", (change,))


def pattern(sha, day, line=1, fingerprint="fp", path=PATH):
    return InsecurePatternFinding(
        fingerprint, "rule", "cat", Severity.HIGH, path, "lib/a", line, sha, moment(day), "b", "m"
    )


def run(commits, patterns=(), secrets=()):
    repository = InMemoryAuditResultRepository()
    repository.save_commits(commits)
    repository.save_pattern_findings(list(patterns))
    repository.save_secret_findings(list(secrets))
    result = TrackFindingLifecycle(repository).execute()
    assert repository.load_finding_lifecycles() == result
    return result


def test_introduced_and_fixed():
    commits = [commit("c1", 1), commit("c2", 2), commit("c3", 3)]
    result = run(commits, [pattern("c1", 1), pattern("c2", 2)])
    assert len(result) == 1
    lifecycle = result[0]
    assert lifecycle.kind == FindingKind.INSECURE_PATTERN
    assert lifecycle.introduced_commit_sha == "c1"
    assert lifecycle.fixed_commit_sha == "c3"
    assert lifecycle.fixed_at == moment(3)
    assert not lifecycle.is_open


def test_deleted_file_closes():
    commits = [commit("c1", 1), commit("c2", 2, blob=None, status=FileChangeStatus.DELETED)]
    result = run(commits, [pattern("c1", 1)])
    assert result[0].fixed_commit_sha == "c2"


def test_line_change_updates_last_seen_line_without_closing():
    commits = [commit("c1", 1), commit("c2", 2)]
    result = run(commits, [pattern("c1", 1, line=3), pattern("c2", 2, line=7)])
    assert len(result) == 1
    assert result[0].is_open
    assert result[0].last_seen_line == 7


def test_reappearance_opens_new_lifecycle():
    commits = [commit("c1", 1), commit("c2", 2), commit("c3", 3)]
    result = run(commits, [pattern("c1", 1), pattern("c3", 3)])
    assert len(result) == 2
    assert result[0].fixed_commit_sha == "c2"
    assert result[1].introduced_commit_sha == "c3"
    assert result[1].is_open


def secret(sha, day, line=1, still=False, head_line=None, removed=None, secret_hash="h"):
    return SecretFinding(
        f"f{sha}", "rule", secret_hash, "cfg.env", sha, moment(day), line, AUTHOR,
        still, head_line, removed, moment(9) if removed else None,
    )


def test_secrets_grouped_with_oldest_as_introduction_and_closed():
    result = run([], secrets=[secret("c2", 2, removed="c5"), secret("c1", 1, line=4, removed="c4")])
    assert len(result) == 1
    lifecycle = result[0]
    expected = hashlib.sha256(b"secret\x00h\x00cfg.env").hexdigest()
    assert lifecycle.fingerprint == expected
    assert lifecycle.kind == FindingKind.SECRET
    assert lifecycle.category == "secret"
    assert lifecycle.severity == Severity.HIGH
    assert lifecycle.introduced_commit_sha == "c1"
    assert lifecycle.fixed_commit_sha == "c4"
    assert lifecycle.last_seen_line == 4


def test_secret_open_when_still_in_head_uses_head_line():
    result = run([], secrets=[secret("c1", 1, line=2, still=True, head_line=8)])
    assert result[0].is_open
    assert result[0].last_seen_line == 8


def test_distinct_secrets_make_distinct_lifecycles():
    result = run([], secrets=[secret("c1", 1), secret("c2", 2, secret_hash="other")])
    assert len(result) == 2

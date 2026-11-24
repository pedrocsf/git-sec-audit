from datetime import datetime, timezone

from domain.entities.author import Author
from domain.entities.commit import Commit
from domain.entities.insecure_pattern_finding import PatternMatch
from domain.entities.severity import Severity
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository

NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)


def build_commit(sha):
    return Commit(sha, Author("n", "e@x.com"), NOW, NOW, (), "s")


def test_save_replaces_previous_content_and_preserves_order():
    repository = InMemoryAuditResultRepository()
    repository.save_commits([build_commit("a"), build_commit("b")])
    assert [c.sha for c in repository.load_commits()] == ["a", "b"]
    repository.save_commits([build_commit("c")])
    assert [c.sha for c in repository.load_commits()] == ["c"]


def test_empty_loads():
    repository = InMemoryAuditResultRepository()
    assert repository.load_dependency_versions() == []
    assert repository.load_finding_lifecycles() == []
    assert repository.load_run_metadata("missing") is None


def test_blob_matches_cache():
    repository = InMemoryAuditResultRepository()
    assert repository.find_blob_matches("s", "b") is None
    repository.save_blob_matches("s", "b", [])
    assert repository.find_blob_matches("s", "b") == []
    match = PatternMatch("r", "c", Severity.LOW, 1, "x", "m")
    repository.save_blob_matches("s", "b2", [match])
    assert repository.find_blob_matches("s", "b2") == [match]
    assert repository.find_blob_matches("other", "b2") is None


def test_run_metadata_by_prefix():
    repository = InMemoryAuditResultRepository()
    repository.save_run_metadata("warning.a", "1")
    repository.save_run_metadata("warning.b", "2")
    repository.save_run_metadata("repository_name", "r")
    assert repository.load_run_metadata_by_prefix("warning.") == {"warning.a": "1", "warning.b": "2"}
    repository.save_run_metadata("warning.a", "3")
    assert repository.load_run_metadata("warning.a") == "3"

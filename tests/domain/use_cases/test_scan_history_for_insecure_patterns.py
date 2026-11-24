from datetime import datetime, timezone

import pytest

from domain.entities.author import Author
from domain.entities.commit import Commit, FileChange, FileChangeStatus
from domain.entities.insecure_pattern_finding import PatternMatch, build_pattern_fingerprint
from domain.entities.severity import Severity
from domain.errors import GitSecAuditError, ScannerUnavailableError
from domain.use_cases.scan_history_for_insecure_patterns import (
    ScanHistoryForInsecurePatterns,
    ScanHistoryForInsecurePatternsRequest,
)
from tests.fakes.fake_git_history_repository import FakeGitHistoryRepository
from tests.fakes.fake_pattern_scanner import FakePatternScanner
from tests.fakes.fake_resource_monitor import FakeResourceMonitor
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository

AUTHOR = Author("Ana", "ana@x.com")
PATH = "lib/features/auth/login.dart"
MATCH = PatternMatch("rule.http", "network", Severity.HIGH, 3, "  http://x  ", "plain http")


def make_commit(sha, day, changes):
    moment = datetime(2024, 1, day, tzinfo=timezone.utc)
    return Commit(sha, AUTHOR, moment, moment, (), "s", tuple(changes))


def change(path, blob):
    return FileChange(path, FileChangeStatus.MODIFIED, None, blob)


def build(commits, scanners, blobs, monitor=None):
    repository = InMemoryAuditResultRepository()
    repository.save_commits(commits)
    monitor = monitor or FakeResourceMonitor()
    use_case = ScanHistoryForInsecurePatterns(
        FakeGitHistoryRepository(blobs=blobs), scanners, repository, monitor
    )
    return use_case, repository, monitor


def test_unique_blob_scanned_once_but_reported_per_commit():
    commits = [
        make_commit("c1", 1, [change(PATH, "b1")]),
        make_commit("c2", 2, [change(PATH, "b1")]),
    ]
    scanner = FakePatternScanner(matches_by_blob={"b1": [MATCH]})
    use_case, repository, _ = build(commits, [scanner], {"b1": b"data"})
    findings = use_case.execute(ScanHistoryForInsecurePatternsRequest())
    assert scanner.scanned_batches == [["b1"]]
    assert [f.commit_sha for f in findings] == ["c1", "c2"]
    assert repository.load_pattern_findings() == findings


def test_fingerprint_and_module_filled():
    commits = [make_commit("c1", 1, [change(PATH, "b1")])]
    scanner = FakePatternScanner(matches_by_blob={"b1": [MATCH]})
    use_case, _, _ = build(commits, [scanner], {"b1": b"data"})
    finding = use_case.execute(ScanHistoryForInsecurePatternsRequest())[0]
    assert finding.fingerprint == build_pattern_fingerprint("rule.http", PATH, "  http://x  ")
    assert finding.module == "lib/features/auth"
    assert finding.blob_sha == "b1"
    assert finding.line == 3


def test_cached_blob_not_rescanned():
    commits = [make_commit("c1", 1, [change(PATH, "b1")])]
    scanner = FakePatternScanner()
    use_case, repository, _ = build(commits, [scanner], {"b1": b"data"})
    repository.save_blob_matches("fake", "b1", [MATCH])
    findings = use_case.execute(ScanHistoryForInsecurePatternsRequest())
    assert scanner.scanned_batches == []
    assert len(findings) == 1


def test_batches_respect_batch_size_and_check_capacity():
    commits = [
        make_commit("c1", 1, [change(PATH, "b1"), change("a.dart", "b2"), change("b.dart", "b3")])
    ]
    blobs = {"b1": b"1234", "b2": b"12", "b3": b"1"}
    scanner = FakePatternScanner()
    use_case, _, monitor = build(commits, [scanner], blobs)
    use_case.execute(ScanHistoryForInsecurePatternsRequest(batch_size=2))
    assert scanner.scanned_batches == [["b1", "b2"], ["b3"]]
    assert monitor.calls == [(12, 24), (2, 4)]


def test_oversized_blob_gets_empty_result_without_scanning():
    commits = [make_commit("c1", 1, [change(PATH, "b1")])]
    scanner = FakePatternScanner(matches_by_blob={"b1": [MATCH]})
    use_case, repository, monitor = build(commits, [scanner], {"b1": b"12345"})
    findings = use_case.execute(ScanHistoryForInsecurePatternsRequest(max_blob_bytes=4))
    assert findings == []
    assert scanner.scanned_batches == []
    assert monitor.calls == []
    assert repository.find_blob_matches("fake", "b1") == []


def test_unavailable_scanner_warns_and_others_continue():
    commits = [make_commit("c1", 1, [change(PATH, "b1")])]
    broken = FakePatternScanner(scanner_id="broken", error=ScannerUnavailableError("no tool"))
    working = FakePatternScanner(scanner_id="ok", matches_by_blob={"b1": [MATCH]})
    use_case, repository, _ = build(commits, [broken, working], {"b1": b"data"})
    findings = use_case.execute(ScanHistoryForInsecurePatternsRequest())
    assert len(findings) == 1
    assert repository.load_run_metadata("warning.patterns.broken") == "no tool"


def test_no_commits_raises():
    use_case, _, _ = build([], [FakePatternScanner()], {})
    with pytest.raises(GitSecAuditError):
        use_case.execute(ScanHistoryForInsecurePatternsRequest())

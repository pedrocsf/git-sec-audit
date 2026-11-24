from datetime import date, datetime, timezone

import pytest

from data.storage.sqlite_audit_result_repository import SqliteAuditResultRepository
from domain.entities.advisory import Advisory
from domain.entities.author import Author
from domain.entities.commit import Commit, FileChange, FileChangeStatus
from domain.entities.dependency_version import DependencyVersion
from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.insecure_pattern_finding import (
    InsecurePatternFinding,
    PatternMatch,
)
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.secret_finding import SecretFinding
from domain.entities.severity import Severity

MOMENT = datetime(2024, 3, 1, 12, 30, tzinfo=timezone.utc)
LATER = datetime(2024, 4, 2, 8, 0, tzinfo=timezone.utc)
AUTHOR = Author("Ana", "ana@example.com")


def build_commit(sha, committed_at=MOMENT):
    return Commit(
        sha=sha,
        author=AUTHOR,
        authored_at=committed_at,
        committed_at=committed_at,
        parent_shas=("p1", "p2"),
        subject="subject",
        file_changes=(
            FileChange("a.py", FileChangeStatus.ADDED, None, "blob1"),
            FileChange("b.py", FileChangeStatus.DELETED, "blob2", None),
        ),
    )


def build_advisory():
    return Advisory(
        advisory_id="GHSA-1",
        aliases=("CVE-2024-1", "X"),
        ecosystem="npm",
        package="lodash",
        summary="bad",
        severity=Severity.CRITICAL,
        published_at=MOMENT,
        fixed_versions=("1.0.1",),
    )


def build_lifecycle(fingerprint, fixed=False):
    return FindingLifecycle(
        fingerprint=fingerprint,
        kind=FindingKind.INSECURE_PATTERN,
        rule_id="r",
        category="c",
        severity=Severity.HIGH,
        file_path="a.py",
        module="lib/x",
        introduced_commit_sha="c1",
        introduced_at=MOMENT,
        fixed_commit_sha="c2" if fixed else None,
        fixed_at=LATER if fixed else None,
        last_seen_line=3,
        introduced_by=AUTHOR,
    )


@pytest.fixture
def repository(tmp_path):
    with SqliteAuditResultRepository(str(tmp_path / "sub" / "audit.db")) as repo:
        yield repo


def test_commits_round_trip_preserves_order(repository):
    commits = [build_commit("z"), build_commit("a", LATER)]
    repository.save_commits(commits)
    assert repository.load_commits() == commits


def test_dependency_versions_round_trip(repository):
    versions = [
        DependencyVersion("npm", "x", "1.0.0", "package-lock.json", "c1", MOMENT, "c2", LATER),
        DependencyVersion("Pub", "y", "2.0.0", "pubspec.lock", "c1", MOMENT, None, None, True),
    ]
    repository.save_dependency_versions(versions)
    assert repository.load_dependency_versions() == versions


def test_patch_lag_records_round_trip(repository):
    records = [
        PatchLagRecord(build_advisory(), "p.lock", "1.0.0", MOMENT, "c1", MOMENT, "1.0.1", "c2", LATER, 1.5, True),
        PatchLagRecord(build_advisory(), "p.lock", "1.0.0", MOMENT, "c1", MOMENT, None, None, None, None),
    ]
    repository.save_patch_lag_records(records)
    assert repository.load_patch_lag_records() == records


def test_libyears_points_round_trip(repository):
    points = [LibyearsPoint(date(2024, 1, 1), 1.25, 3), LibyearsPoint(date(2024, 2, 1), 2.5, 4)]
    repository.save_libyears_points(points)
    assert repository.load_libyears_points() == points


def test_secret_findings_round_trip(repository):
    findings = [
        SecretFinding("f1", "r", "h", "a.env", "c1", MOMENT, 2, AUTHOR, True, 4, None, None),
        SecretFinding("f2", "r", "h2", "b.env", "c1", MOMENT, 2, AUTHOR, False, None, "c2", LATER),
    ]
    repository.save_secret_findings(findings)
    assert repository.load_secret_findings() == findings


def test_pattern_findings_round_trip(repository):
    findings = [
        InsecurePatternFinding("f1", "r", "c", Severity.LOW, "a.py", "lib/x", 5, "c1", MOMENT, "b1", "msg"),
        InsecurePatternFinding("f2", "r", "c", Severity.UNKNOWN, "b.py", "lib/y", 6, "c2", LATER, "b2", "msg"),
    ]
    repository.save_pattern_findings(findings)
    assert repository.load_pattern_findings() == findings


def test_lifecycles_round_trip_with_repeated_fingerprint(repository):
    lifecycles = [
        build_lifecycle("same", fixed=True),
        build_lifecycle("same"),
        FindingLifecycle("s", FindingKind.SECRET, "r", "secret", Severity.HIGH, "a", "m", "c1", MOMENT, None, None, 1),
    ]
    repository.save_finding_lifecycles(lifecycles)
    assert repository.load_finding_lifecycles() == lifecycles


def test_save_replaces_previous_content(repository):
    repository.save_commits([build_commit("a"), build_commit("b")])
    repository.save_commits([build_commit("c")])
    assert [commit.sha for commit in repository.load_commits()] == ["c"]
    repository.save_commits([])
    assert repository.load_commits() == []


def test_data_persists_after_reopening(tmp_path):
    path = str(tmp_path / "audit.db")
    first = SqliteAuditResultRepository(path)
    first.save_commits([build_commit("a")])
    first.save_run_metadata("k", "v")
    first.save_blob_matches("s", "b", [])
    first.close()
    with SqliteAuditResultRepository(path) as second:
        assert [commit.sha for commit in second.load_commits()] == ["a"]
        assert second.load_run_metadata("k") == "v"
        assert second.find_blob_matches("s", "b") == []


def test_blob_matches_cache(repository):
    assert repository.find_blob_matches("s", "b") is None
    repository.save_blob_matches("s", "b", [])
    assert repository.find_blob_matches("s", "b") == []
    matches = [PatternMatch("r", "c", Severity.MEDIUM, 3, "line", "msg")]
    repository.save_blob_matches("s", "b", matches)
    assert repository.find_blob_matches("s", "b") == matches
    assert repository.find_blob_matches("other", "b") is None


def test_run_metadata_upsert_and_prefix(repository):
    assert repository.load_run_metadata("missing") is None
    repository.save_run_metadata("warning.secrets", "one")
    repository.save_run_metadata("warning.secrets", "two")
    repository.save_run_metadata("warning.patterns.x", "three")
    repository.save_run_metadata("warningX", "no")
    repository.save_run_metadata("repository_name", "repo")
    assert repository.load_run_metadata("warning.secrets") == "two"
    assert repository.load_run_metadata_by_prefix("warning.") == {
        "warning.secrets": "two",
        "warning.patterns.x": "three",
    }

from datetime import datetime, timedelta, timezone

from domain.entities.advisory import Advisory
from domain.entities.author import Author
from domain.entities.commit import Commit
from domain.entities.dependency_version import DependencyVersion
from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.severity import Severity
from domain.use_cases.build_security_report import (
    BuildSecurityReport,
    BuildSecurityReportRequest,
)
from tests.fakes.in_memory_audit_result_repository import (
    InMemoryAuditResultRepository,
)

START = datetime(2024, 1, 1, tzinfo=timezone.utc)
AS_OF = START + timedelta(days=100)
ALICE = Author("Alice", "alice@example.com")
BOB = Author("Bob", "bob@example.com")


def day(offset):
    return START + timedelta(days=offset)


def make_commit(sha, author, offset):
    return Commit(sha, author, day(offset), day(offset), (), "subject")


def make_record(severity, start, fixed, lag, published=0):
    advisory = Advisory(
        "GHSA-1", ("CVE-1",), "npm", "pkg", "s", severity, day(published), ()
    )
    return PatchLagRecord(
        advisory=advisory,
        lockfile_path="package-lock.json",
        vulnerable_version="1.0.0",
        exposure_started_at=day(start),
        exposure_start_commit_sha="a",
        reference_at=day(published),
        fixed_version=None,
        fix_commit_sha=None if fixed is None else "f",
        fixed_at=None if fixed is None else day(fixed),
        lag_days=lag,
    )


def make_finding(category, module, offset, fixed, author, fingerprint="fp"):
    return FindingLifecycle(
        fingerprint=fingerprint,
        kind=FindingKind.INSECURE_PATTERN,
        rule_id="r",
        category=category,
        severity=Severity.HIGH,
        file_path=f"{module}/a.py",
        module=module,
        introduced_commit_sha="c",
        introduced_at=day(offset),
        fixed_commit_sha=None if fixed is None else "d",
        fixed_at=None if fixed is None else day(fixed),
        last_seen_line=1,
        introduced_by=author,
    )


def build(repository, include_authors=False, anonymize=False):
    request = BuildSecurityReportRequest(AS_OF, include_authors, anonymize)
    return BuildSecurityReport(repository).execute(request)


def test_median_p90_and_open_counts():
    repository = InMemoryAuditResultRepository()
    lags = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    records = [make_record(Severity.HIGH, 0, 5, lag) for lag in lags]
    records.append(make_record(Severity.HIGH, 0, None, None))
    records.append(make_record(Severity.LOW, 0, 5, 3.0))
    repository.save_patch_lag_records(records)
    report = build(repository)
    high, low = report.patch_lag_summaries
    assert high.severity == Severity.HIGH
    assert high.total == 11
    assert high.open_count == 1
    assert high.median_lag_days == 55.0
    assert high.p90_lag_days == 90.0
    assert low.severity == Severity.LOW
    assert low.median_lag_days == 3.0


def test_summary_without_closed_has_none():
    repository = InMemoryAuditResultRepository()
    repository.save_patch_lag_records([make_record(Severity.HIGH, 0, None, None)])
    summary = build(repository).patch_lag_summaries[0]
    assert summary.median_lag_days is None
    assert summary.p90_lag_days is None


def test_critical_exposure_overlapping_and_clipped():
    repository = InMemoryAuditResultRepository()
    repository.save_commits([make_commit("a", ALICE, 10)])
    repository.save_patch_lag_records(
        [
            make_record(Severity.CRITICAL, 0, 40, 40.0),
            make_record(Severity.CRITICAL, 30, 60, 30.0),
            make_record(Severity.HIGH, 0, None, None),
        ]
    )
    report = build(repository)
    assert report.critical_exposure_percentage == round(50 / 90 * 100, 2)


def test_critical_exposure_open_until_as_of_and_published_bound():
    repository = InMemoryAuditResultRepository()
    repository.save_commits([make_commit("a", ALICE, 0)])
    repository.save_patch_lag_records(
        [make_record(Severity.CRITICAL, 0, None, None, published=50)]
    )
    assert build(repository).critical_exposure_percentage == 50.0


def test_critical_exposure_none_without_commits():
    repository = InMemoryAuditResultRepository()
    assert build(repository).critical_exposure_percentage is None


def test_groupings_and_mean_time_to_fix():
    repository = InMemoryAuditResultRepository()
    repository.save_finding_lifecycles(
        [
            make_finding("crypto", "lib/a", 1, 11, ALICE),
            make_finding("crypto", "lib/a", 2, 32, ALICE),
            make_finding("net", "lib/b", 40, None, BOB),
        ]
    )
    report = build(repository)
    assert report.findings_by_category == (("crypto", 2), ("net", 1))
    assert report.findings_by_module == (("lib/a", 2), ("lib/b", 1))
    assert report.findings_by_month == (("2024-01", 2), ("2024-02", 1))
    assert report.mean_time_to_fix_days == 20.0


def test_mean_time_to_fix_none_when_all_open():
    repository = InMemoryAuditResultRepository()
    repository.save_finding_lifecycles([make_finding("net", "lib/b", 40, None, BOB)])
    assert build(repository).mean_time_to_fix_days is None


def prepare_ranking_repository():
    repository = InMemoryAuditResultRepository()
    repository.save_commits(
        [make_commit("1", ALICE, 0), make_commit("2", ALICE, 1), make_commit("3", BOB, 2)]
    )
    repository.save_finding_lifecycles(
        [
            make_finding("x", "m", 1, None, ALICE),
            make_finding("x", "m", 2, None, BOB),
            make_finding("x", "m", 3, None, BOB),
        ]
    )
    return repository


def test_author_ranking_with_names():
    report = build(prepare_ranking_repository(), include_authors=True)
    first, second = report.author_rankings
    assert first.author_label == "Bob"
    assert first.finding_count == 2
    assert first.commit_count == 1
    assert first.findings_per_commit == 2.0
    assert second.author_label == "Alice"
    assert second.findings_per_commit == 0.5


def test_author_ranking_anonymized():
    report = build(prepare_ranking_repository(), include_authors=True, anonymize=True)
    assert [r.author_label for r in report.author_rankings] == ["Autor 1", "Autor 2"]


def test_author_ranking_excluded_by_default():
    assert build(prepare_ranking_repository()).author_rankings == ()


def test_warnings_and_repository_name():
    repository = InMemoryAuditResultRepository()
    repository.save_run_metadata("warning.secrets", "gitleaks missing")
    repository.save_run_metadata("repository_name", "demo")
    report = build(repository)
    assert report.repository_name == "demo"
    assert "gitleaks missing" in report.warnings
    assert "Nenhum lockfile encontrado no histórico" in report.warnings


def test_approximated_warning_and_default_name():
    repository = InMemoryAuditResultRepository()
    repository.save_dependency_versions(
        [DependencyVersion("Pub", "p", "1.0.0", "pubspec.lock", "a", day(0), None, None, True)]
    )
    report = build(repository)
    assert report.repository_name == "unknown"
    assert report.warnings == ("Versões aproximadas a partir do pubspec.yaml",)

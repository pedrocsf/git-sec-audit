from datetime import datetime, timezone

import pytest

from domain.entities.advisory import Advisory
from domain.entities.dependency_version import DependencyVersion
from domain.entities.package_release import PackageRelease
from domain.entities.severity import Severity
from domain.use_cases.calculate_patch_lag import CalculatePatchLag, CalculatePatchLagRequest
from tests.fakes.fake_advisory_repository import FakeAdvisoryRepository
from tests.fakes.fake_package_release_repository import FakePackageReleaseRepository
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository

LOCK = "pubspec.lock"
AS_OF = datetime(2024, 12, 31, tzinfo=timezone.utc)


def at(month, day):
    return datetime(2024, month, day, tzinfo=timezone.utc)


def advisory(published_at, fixed=("1.1.0",), advisory_id="GHSA-1"):
    return Advisory(
        advisory_id, ("CVE-2024-1",), "Pub", "a", "s", Severity.HIGH, published_at, fixed
    )


def interval(version, start, end, start_sha, end_sha, package="a", path=LOCK):
    return DependencyVersion(
        "Pub", package, version, path, start_sha, start, end_sha, end
    )


def run(versions, advisories, releases=(), as_of=AS_OF):
    results = InMemoryAuditResultRepository()
    results.save_dependency_versions(versions)
    advisory_repository = FakeAdvisoryRepository(advisories)
    use_case = CalculatePatchLag(
        advisory_repository, FakePackageReleaseRepository(list(releases)), results
    )
    records = use_case.execute(CalculatePatchLagRequest(as_of))
    return records, results, advisory_repository


def test_fix_by_upgrade():
    adv = advisory(at(2, 1))
    versions = [
        interval("1.0.0", at(1, 1), at(3, 1), "c1", "c2"),
        interval("1.1.0", at(3, 1), None, "c2", None),
    ]

    records, results, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]})

    assert len(records) == 1
    record = records[0]
    assert record.lag_days == 29.0
    assert record.reference_at == at(2, 1)
    assert record.fixed_version == "1.1.0"
    assert record.fix_commit_sha == "c2"
    assert record.fixed_at == at(3, 1)
    assert record.vulnerable_version == "1.0.0"
    assert record.exposure_started_at == at(1, 1)
    assert record.exposure_start_commit_sha == "c1"
    assert not record.fixed_before_disclosure
    assert results.load_patch_lag_records() == records


def test_fixed_before_disclosure():
    adv = advisory(at(3, 1))
    versions = [
        interval("1.0.0", at(1, 1), at(2, 1), "c1", "c2"),
        interval("1.1.0", at(2, 1), None, "c2", None),
    ]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]})

    assert records[0].lag_days == 0.0
    assert records[0].fixed_before_disclosure


def test_release_after_advisory_is_reference():
    adv = advisory(at(2, 1))
    versions = [
        interval("1.0.0", at(1, 1), at(3, 1), "c1", "c2"),
        interval("1.1.0", at(3, 1), None, "c2", None),
    ]
    release = PackageRelease("Pub", "a", "1.1.0", at(2, 11))

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]}, [release])

    assert records[0].reference_at == at(2, 11)
    assert records[0].lag_days == 19.0


def test_open_exposure():
    adv = advisory(at(2, 1))
    versions = [interval("1.0.0", at(1, 1), None, "c1", None)]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]})

    assert records[0].is_open
    assert records[0].lag_days is None
    assert records[0].fixed_version is None
    assert records[0].fixed_at is None


def test_package_removal_has_no_fixed_version():
    adv = advisory(at(2, 1))
    versions = [interval("1.0.0", at(1, 1), at(4, 1), "c1", "c2")]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]})

    assert records[0].fixed_version is None
    assert records[0].fix_commit_sha == "c2"
    assert records[0].lag_days == 60.0


def test_two_separate_exposure_periods():
    adv = advisory(at(1, 1))
    versions = [
        interval("1.0.0", at(1, 1), at(2, 1), "c1", "c2"),
        interval("1.1.0", at(2, 1), at(5, 1), "c2", "c3"),
        interval("1.0.0", at(5, 1), None, "c3", None),
    ]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]})

    assert len(records) == 2
    assert records[0].fix_commit_sha == "c2"
    assert records[0].fixed_version == "1.1.0"
    assert records[0].lag_days == 31.0
    assert records[1].is_open
    assert records[1].exposure_started_at == at(5, 1)


def test_overlapping_versions_merge_into_one_period():
    adv = advisory(at(1, 1), fixed=("2.0.0",))
    versions = [
        interval("1.0.0", at(1, 1), at(3, 1), "c1", "c3"),
        interval("1.5.0", at(2, 1), at(4, 1), "c2", "c4"),
    ]
    advisories = {("Pub", "a", "1.0.0"): [adv], ("Pub", "a", "1.5.0"): [adv]}

    records, _, _ = run(versions, advisories)

    assert len(records) == 1
    assert records[0].fix_commit_sha == "c4"
    assert records[0].fixed_at == at(4, 1)


def test_prefetch_receives_distinct_tuples():
    versions = [
        interval("1.0.0", at(1, 1), at(2, 1), "c1", "c2"),
        interval("1.0.0", at(3, 1), None, "c3", None),
        interval("2.0.0", at(2, 1), None, "c2", None),
    ]

    _, _, advisory_repository = run(versions, {})

    assert sorted(advisory_repository.prefetched) == [
        ("Pub", "a", "1.0.0"),
        ("Pub", "a", "2.0.0"),
    ]
    assert len(advisory_repository.prefetched) == 2


def test_advisory_published_after_as_of_is_ignored():
    adv = advisory(at(6, 1))
    versions = [interval("1.0.0", at(1, 1), None, "c1", None)]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]}, as_of=at(3, 1))

    assert records == []


def test_fix_after_as_of_becomes_open_record():
    adv = advisory(at(2, 1))
    versions = [
        interval("1.0.0", at(1, 1), at(5, 1), "c1", "c2"),
        interval("1.1.0", at(5, 1), None, "c2", None),
    ]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]}, as_of=at(3, 1))

    assert len(records) == 1
    assert records[0].is_open
    assert records[0].fixed_at is None
    assert records[0].fix_commit_sha is None


def test_interval_starting_after_as_of_is_ignored():
    adv = advisory(at(2, 1))
    versions = [interval("1.0.0", at(6, 1), None, "c1", None)]

    records, _, _ = run(versions, {("Pub", "a", "1.0.0"): [adv]}, as_of=at(3, 1))

    assert records == []


def test_as_of_after_everything_preserves_behavior():
    adv = advisory(at(2, 1))
    versions = [
        interval("1.0.0", at(1, 1), at(3, 1), "c1", "c2"),
        interval("1.1.0", at(3, 1), None, "c2", None),
    ]

    records, _, _ = run(
        versions,
        {("Pub", "a", "1.0.0"): [adv]},
        as_of=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )

    assert len(records) == 1
    assert records[0].lag_days == 29.0
    assert records[0].fixed_version == "1.1.0"

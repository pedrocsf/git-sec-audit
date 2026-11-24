from datetime import date, datetime, timezone

from domain.entities.dependency_version import DependencyVersion
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.package_release import PackageRelease
from domain.use_cases.calculate_libyears import CalculateLibyears, CalculateLibyearsRequest
from tests.fakes.fake_package_release_repository import FakePackageReleaseRepository
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository


def at(year, month, day):
    return datetime(year, month, day, tzinfo=timezone.utc)


def release(version, moment, package="a"):
    return PackageRelease("Pub", package, version, moment)


def dependency(version, start, end=None, package="a"):
    return DependencyVersion("Pub", package, version, "pubspec.lock", "s", start, None, end)


def run(versions, releases, as_of):
    results = InMemoryAuditResultRepository()
    results.save_dependency_versions(versions)
    use_case = CalculateLibyears(FakePackageReleaseRepository(releases), results)
    points = use_case.execute(CalculateLibyearsRequest(as_of))
    return points, results


def test_known_monthly_values():
    releases = [
        release("1.0.0", at(2023, 1, 1)),
        release("1.1.0", at(2023, 7, 2)),
        release("2.0.0", at(2024, 2, 15)),
    ]
    versions = [dependency("1.0.0", at(2024, 1, 10))]

    points, results = run(versions, releases, at(2024, 3, 15))

    assert [p.month for p in points] == [date(2024, 1, 1), date(2024, 2, 1), date(2024, 3, 1)]
    assert points[0] == LibyearsPoint(date(2024, 1, 1), 0.5, 1)
    assert points[1] == LibyearsPoint(date(2024, 2, 1), 1.12, 1)
    assert points[2] == LibyearsPoint(date(2024, 3, 1), 1.12, 1)
    assert results.load_libyears_points() == points


def test_releases_after_instant_and_prereleases_are_ignored():
    releases = [
        release("1.0.0", at(2023, 1, 1)),
        release("2.0.0-beta.1", at(2023, 6, 1)),
        release("1.2.0", at(2024, 1, 1)),
    ]
    versions = [dependency("1.0.0", at(2023, 1, 5))]

    points, _ = run(versions, releases, at(2024, 1, 20))

    by_month = {p.month: p.libyears for p in points}
    assert by_month[date(2023, 11, 1)] == 0.0
    assert by_month[date(2024, 1, 1)] == 1.0


def test_unknown_release_is_ignored():
    releases = [release("1.0.0", at(2023, 1, 1)), release("2.0.0", at(2024, 1, 1))]
    versions = [
        dependency("1.0.0", at(2024, 2, 1)),
        dependency("9.9.9", at(2024, 2, 1), package="a"),
    ]

    points, _ = run(versions, releases, at(2024, 2, 20))

    assert points == [LibyearsPoint(date(2024, 2, 1), 1.0, 1)]


def test_closed_interval_not_active_after_end():
    releases = [release("1.0.0", at(2023, 1, 1)), release("2.0.0", at(2024, 1, 1))]
    versions = [dependency("1.0.0", at(2024, 1, 5), at(2024, 2, 10))]

    points, _ = run(versions, releases, at(2024, 3, 20))

    assert [p.package_count for p in points] == [1, 0, 0]


def test_no_versions_yields_no_points():
    points, _ = run([], [], at(2024, 3, 20))

    assert points == []

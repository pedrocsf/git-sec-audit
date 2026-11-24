from dataclasses import dataclass
from datetime import date, datetime, timezone

from domain.entities.dependency_version import DependencyVersion
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.package_release import PackageRelease
from domain.entities.semantic_version import SemanticVersion
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.package_release_repository import PackageReleaseRepository

DAYS_PER_YEAR = 365.25
DECIMAL_PLACES = 2
MONTHS_PER_YEAR = 12


@dataclass(frozen=True)
class CalculateLibyearsRequest:
    as_of: datetime


class CalculateLibyears:
    def __init__(
        self,
        package_release_repository: PackageReleaseRepository,
        audit_result_repository: AuditResultRepository,
    ) -> None:
        self._package_release_repository = package_release_repository
        self._audit_result_repository = audit_result_repository
        self._releases_cache: dict[tuple[str, str], list[PackageRelease]] = {}

    def execute(self, request: CalculateLibyearsRequest) -> list[LibyearsPoint]:
        versions = self._audit_result_repository.load_dependency_versions()
        points = [
            self._point_for_month(versions, month, request.as_of)
            for month in _months(versions, request.as_of)
        ]
        self._audit_result_repository.save_libyears_points(points)
        return points

    def _point_for_month(
        self, versions: list[DependencyVersion], month: date, as_of: datetime
    ) -> LibyearsPoint:
        instant = min(_next_month_start(month), as_of)
        active = {
            (v.ecosystem, v.package, v.version)
            for v in versions
            if v.start_at <= instant and (v.end_at is None or v.end_at > instant)
        }
        total = 0.0
        counted = 0
        for ecosystem, package, version in sorted(active):
            lag = self._lag_years(ecosystem, package, version, instant)
            if lag is None:
                continue
            total += lag
            counted += 1
        return LibyearsPoint(month, round(total, DECIMAL_PLACES), counted)

    def _lag_years(
        self, ecosystem: str, package: str, version: str, instant: datetime
    ) -> float | None:
        used = self._package_release_repository.find_release(ecosystem, package, version)
        if used is None:
            return None
        latest = self._latest_release(ecosystem, package, instant)
        if latest is None:
            return 0.0
        return max(0.0, (latest.released_at - used.released_at).days / DAYS_PER_YEAR)

    def _latest_release(
        self, ecosystem: str, package: str, instant: datetime
    ) -> PackageRelease | None:
        key = (ecosystem, package)
        if key not in self._releases_cache:
            self._releases_cache[key] = self._package_release_repository.list_releases(
                ecosystem, package
            )
        best: tuple[SemanticVersion, PackageRelease] | None = None
        for release in self._releases_cache[key]:
            parsed = SemanticVersion.parse(release.version)
            if parsed is None or parsed.is_prerelease or release.released_at > instant:
                continue
            if best is None or parsed > best[0]:
                best = (parsed, release)
        return best[1] if best else None


def _next_month_start(month: date) -> datetime:
    year = month.year + month.month // MONTHS_PER_YEAR
    next_month = month.month % MONTHS_PER_YEAR + 1
    return datetime(year, next_month, 1, tzinfo=timezone.utc)


def _months(versions: list[DependencyVersion], as_of: datetime) -> list[date]:
    if not versions:
        return []
    first = min(v.start_at for v in versions)
    current = date(first.year, first.month, 1)
    last = date(as_of.year, as_of.month, 1)
    months = []
    while current <= last:
        months.append(current)
        next_start = _next_month_start(current)
        current = date(next_start.year, next_start.month, 1)
    return months

from dataclasses import dataclass, replace
from datetime import datetime

from domain.entities.advisory import Advisory
from domain.entities.dependency_version import DependencyVersion
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.semantic_version import SemanticVersion
from domain.repositories.advisory_repository import AdvisoryRepository
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.package_release_repository import PackageReleaseRepository

SECONDS_PER_DAY = 86400


@dataclass(frozen=True)
class CalculatePatchLagRequest:
    as_of: datetime


class CalculatePatchLag:
    def __init__(
        self,
        advisory_repository: AdvisoryRepository,
        package_release_repository: PackageReleaseRepository,
        audit_result_repository: AuditResultRepository,
    ) -> None:
        self._advisory_repository = advisory_repository
        self._package_release_repository = package_release_repository
        self._audit_result_repository = audit_result_repository

    def execute(self, request: CalculatePatchLagRequest) -> list[PatchLagRecord]:
        self._as_of = request.as_of
        versions = _clamp_to_as_of(
            self._audit_result_repository.load_dependency_versions(), request.as_of
        )
        queries = sorted({(v.ecosystem, v.package, v.version) for v in versions})
        self._advisory_repository.prefetch(queries)
        records: list[PatchLagRecord] = []
        for group in _group_versions(versions).values():
            records.extend(self._records_for_group(group))
        records.sort(key=lambda record: record.exposure_started_at)
        self._audit_result_repository.save_patch_lag_records(records)
        return records

    def _records_for_group(self, group: list[DependencyVersion]) -> list[PatchLagRecord]:
        affected: dict[str, tuple[Advisory, list[DependencyVersion]]] = {}
        for version in group:
            for advisory in self._advisories_of(version):
                affected.setdefault(advisory.advisory_id, (advisory, []))[1].append(version)
        records: list[PatchLagRecord] = []
        for advisory, intervals in affected.values():
            for period in _merge_periods(intervals):
                records.append(self._build_record(advisory, period, group))
        return records

    def _advisories_of(self, version: DependencyVersion) -> list[Advisory]:
        advisories = self._advisory_repository.find_advisories(
            version.ecosystem, version.package, version.version
        )
        return [item for item in advisories if item.published_at <= self._as_of]

    def _build_record(
        self,
        advisory: Advisory,
        period: list[DependencyVersion],
        group: list[DependencyVersion],
    ) -> PatchLagRecord:
        first = period[0]
        reference_at = self._reference_at(advisory, first)
        if any(interval.end_at is None for interval in period):
            return PatchLagRecord(
                advisory=advisory,
                lockfile_path=first.lockfile_path,
                vulnerable_version=first.version,
                exposure_started_at=first.start_at,
                exposure_start_commit_sha=first.start_commit_sha,
                reference_at=reference_at,
                fixed_version=None,
                fix_commit_sha=None,
                fixed_at=None,
                lag_days=None,
            )
        last = max(period, key=lambda interval: interval.end_at)
        lag_days = (last.end_at - reference_at).total_seconds() / SECONDS_PER_DAY
        return PatchLagRecord(
            advisory=advisory,
            lockfile_path=first.lockfile_path,
            vulnerable_version=first.version,
            exposure_started_at=first.start_at,
            exposure_start_commit_sha=first.start_commit_sha,
            reference_at=reference_at,
            fixed_version=self._fixed_version(advisory, last, group),
            fix_commit_sha=last.end_commit_sha,
            fixed_at=last.end_at,
            lag_days=max(lag_days, 0.0),
            fixed_before_disclosure=lag_days < 0,
        )

    def _fixed_version(
        self, advisory: Advisory, last: DependencyVersion, group: list[DependencyVersion]
    ) -> str | None:
        for candidate in group:
            if candidate.start_commit_sha != last.end_commit_sha:
                continue
            ids = {item.advisory_id for item in self._advisories_of(candidate)}
            if advisory.advisory_id not in ids:
                return candidate.version
        return None

    def _reference_at(self, advisory: Advisory, first: DependencyVersion) -> datetime:
        fixed_version = _smallest_fix_above(advisory, first.version)
        if fixed_version is None:
            return advisory.published_at
        release = self._package_release_repository.find_release(
            first.ecosystem, first.package, fixed_version
        )
        if release is None:
            return advisory.published_at
        return max(advisory.published_at, release.released_at)


def _clamp_to_as_of(
    versions: list[DependencyVersion], as_of: datetime
) -> list[DependencyVersion]:
    clamped: list[DependencyVersion] = []
    for version in versions:
        if version.start_at > as_of:
            continue
        if version.end_at is not None and version.end_at > as_of:
            version = replace(version, end_at=None, end_commit_sha=None)
        clamped.append(version)
    return clamped


def _group_versions(
    versions: list[DependencyVersion],
) -> dict[tuple[str, str, str], list[DependencyVersion]]:
    groups: dict[tuple[str, str, str], list[DependencyVersion]] = {}
    for version in versions:
        key = (version.ecosystem, version.package, version.lockfile_path)
        groups.setdefault(key, []).append(version)
    return groups


def _merge_periods(intervals: list[DependencyVersion]) -> list[list[DependencyVersion]]:
    periods: list[list[DependencyVersion]] = []
    period_end: datetime | None = None
    for interval in sorted(intervals, key=lambda item: item.start_at):
        if periods and (period_end is None or interval.start_at <= period_end):
            periods[-1].append(interval)
            period_end = None if period_end is None or interval.end_at is None else max(period_end, interval.end_at)
            continue
        periods.append([interval])
        period_end = interval.end_at
    return periods


def _smallest_fix_above(advisory: Advisory, vulnerable_version: str) -> str | None:
    vulnerable = SemanticVersion.parse(vulnerable_version)
    if vulnerable is None:
        return None
    candidates = []
    for text in advisory.fixed_versions:
        parsed = SemanticVersion.parse(text)
        if parsed is not None and parsed > vulnerable:
            candidates.append((parsed, text))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]

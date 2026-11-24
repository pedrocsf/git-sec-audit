import math
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from domain.entities.author import Author
from domain.entities.finding_lifecycle import FindingLifecycle
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.security_report import (
    AuthorRanking,
    PatchLagSummary,
    SecurityReport,
)
from domain.entities.severity import Severity
from domain.repositories.audit_result_repository import AuditResultRepository

P90_FRACTION = 0.9
PERCENTAGE_FACTOR = 100
PERCENTAGE_DECIMALS = 2
RATIO_DECIMALS = 4
MONTH_FORMAT = "%Y-%m"
UNKNOWN_REPOSITORY_NAME = "unknown"
REPOSITORY_NAME_KEY = "repository_name"
WARNING_PREFIX = "warning."
ANONYMOUS_LABEL_PREFIX = "Autor"
APPROXIMATED_WARNING = "Versões aproximadas a partir do pubspec.yaml"
NO_LOCKFILE_WARNING = "Nenhum lockfile encontrado no histórico"


@dataclass(frozen=True)
class BuildSecurityReportRequest:
    as_of: datetime
    include_authors: bool
    anonymize_authors: bool


class BuildSecurityReport:
    def __init__(self, audit_result_repository: AuditResultRepository) -> None:
        self._audit_result_repository = audit_result_repository

    def execute(self, request: BuildSecurityReportRequest) -> SecurityReport:
        repository = self._audit_result_repository
        records = tuple(repository.load_patch_lag_records())
        findings = tuple(repository.load_finding_lifecycles())
        commits = repository.load_commits()
        versions = repository.load_dependency_versions()
        window_start = commits[0].committed_at if commits else None
        return SecurityReport(
            generated_at=request.as_of,
            repository_name=repository.load_run_metadata(REPOSITORY_NAME_KEY)
            or UNKNOWN_REPOSITORY_NAME,
            patch_lag_records=records,
            patch_lag_summaries=self._summarize_patch_lag(records),
            critical_exposure_percentage=self._critical_exposure(
                records, window_start, request.as_of
            ),
            libyears_curve=tuple(repository.load_libyears_points()),
            findings=findings,
            findings_by_category=self._count_descending(
                finding.category for finding in findings
            ),
            findings_by_module=self._count_descending(
                finding.module for finding in findings
            ),
            findings_by_month=self._count_by_month(findings),
            mean_time_to_fix_days=self._mean_time_to_fix(findings, request.as_of),
            author_rankings=self._rank_authors(findings, commits, request),
            warnings=self._collect_warnings(versions),
        )

    def _summarize_patch_lag(
        self, records: tuple[PatchLagRecord, ...]
    ) -> tuple[PatchLagSummary, ...]:
        severities = sorted(
            {record.severity for record in records},
            key=lambda severity: severity.rank,
            reverse=True,
        )
        return tuple(
            self._summarize_severity(
                severity, [r for r in records if r.severity == severity]
            )
            for severity in severities
        )

    def _summarize_severity(
        self, severity: Severity, records: list[PatchLagRecord]
    ) -> PatchLagSummary:
        lags = sorted(
            record.lag_days
            for record in records
            if not record.is_open and record.lag_days is not None
        )
        return PatchLagSummary(
            severity=severity,
            total=len(records),
            open_count=sum(1 for record in records if record.is_open),
            median_lag_days=statistics.median(lags) if lags else None,
            p90_lag_days=self._nearest_rank(lags, P90_FRACTION),
        )

    def _nearest_rank(self, sorted_values: list[float], fraction: float) -> float | None:
        if not sorted_values:
            return None
        index = math.ceil(fraction * len(sorted_values)) - 1
        return sorted_values[index]

    def _critical_exposure(
        self,
        records: tuple[PatchLagRecord, ...],
        window_start: datetime | None,
        as_of: datetime,
    ) -> float | None:
        if window_start is None:
            return None
        window_seconds = (as_of - window_start).total_seconds()
        if window_seconds <= 0:
            return 0.0
        intervals = self._clipped_critical_intervals(records, window_start, as_of)
        covered = sum((end - start).total_seconds() for start, end in intervals)
        return round(
            covered / window_seconds * PERCENTAGE_FACTOR, PERCENTAGE_DECIMALS
        )

    def _clipped_critical_intervals(
        self,
        records: tuple[PatchLagRecord, ...],
        window_start: datetime,
        as_of: datetime,
    ) -> list[tuple[datetime, datetime]]:
        intervals = []
        for record in records:
            if record.severity != Severity.CRITICAL:
                continue
            start = max(
                record.exposure_started_at, record.advisory.published_at, window_start
            )
            end = min(record.fixed_at or as_of, as_of)
            if end > start:
                intervals.append((start, end))
        return self._merge_intervals(intervals)

    def _merge_intervals(
        self, intervals: list[tuple[datetime, datetime]]
    ) -> list[tuple[datetime, datetime]]:
        merged: list[tuple[datetime, datetime]] = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                continue
            merged.append((start, end))
        return merged

    def _count_descending(self, values) -> tuple[tuple[str, int], ...]:
        counts = Counter(values)
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return tuple(ordered)

    def _count_by_month(
        self, findings: tuple[FindingLifecycle, ...]
    ) -> tuple[tuple[str, int], ...]:
        counts = Counter(
            finding.introduced_at.strftime(MONTH_FORMAT) for finding in findings
        )
        return tuple(sorted(counts.items()))

    def _mean_time_to_fix(
        self, findings: tuple[FindingLifecycle, ...], as_of: datetime
    ) -> float | None:
        lifetimes = [
            finding.lifetime_days(as_of) for finding in findings if not finding.is_open
        ]
        if not lifetimes:
            return None
        return statistics.fmean(lifetimes)

    def _rank_authors(
        self, findings, commits, request: BuildSecurityReportRequest
    ) -> tuple[AuthorRanking, ...]:
        if not request.include_authors:
            return ()
        finding_counts: Counter[str] = Counter()
        names: dict[str, str] = {}
        for finding in findings:
            author: Author | None = finding.introduced_by
            if author is None:
                continue
            finding_counts[author.identity] += 1
            names.setdefault(author.identity, author.name)
        commit_counts = Counter(commit.author.identity for commit in commits)
        entries = []
        for identity, finding_count in finding_counts.items():
            commit_count = commit_counts.get(identity, 0)
            ratio = finding_count / commit_count if commit_count else 0.0
            entries.append((identity, finding_count, commit_count, ratio))
        entries.sort(key=lambda entry: (-entry[3], -entry[1], entry[0]))
        return tuple(
            AuthorRanking(
                author_label=self._label(
                    position, names[identity], request.anonymize_authors
                ),
                finding_count=finding_count,
                commit_count=commit_count,
                findings_per_commit=round(ratio, RATIO_DECIMALS),
            )
            for position, (identity, finding_count, commit_count, ratio) in enumerate(
                entries, start=1
            )
        )

    def _label(self, position: int, name: str, anonymize: bool) -> str:
        if anonymize:
            return f"{ANONYMOUS_LABEL_PREFIX} {position}"
        return name

    def _collect_warnings(self, versions) -> tuple[str, ...]:
        warnings = list(
            self._audit_result_repository.load_run_metadata_by_prefix(
                WARNING_PREFIX
            ).values()
        )
        if any(version.approximated for version in versions):
            warnings.append(APPROXIMATED_WARNING)
        if not versions:
            warnings.append(NO_LOCKFILE_WARNING)
        return tuple(warnings)

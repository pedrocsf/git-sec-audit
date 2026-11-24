from dataclasses import dataclass
from datetime import datetime

from domain.entities.finding_lifecycle import FindingLifecycle
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.severity import Severity


@dataclass(frozen=True)
class PatchLagSummary:
    severity: Severity
    total: int
    open_count: int
    median_lag_days: float | None
    p90_lag_days: float | None


@dataclass(frozen=True)
class AuthorRanking:
    author_label: str
    finding_count: int
    commit_count: int
    findings_per_commit: float


@dataclass(frozen=True)
class SecurityReport:
    generated_at: datetime
    repository_name: str
    patch_lag_records: tuple[PatchLagRecord, ...]
    patch_lag_summaries: tuple[PatchLagSummary, ...]
    critical_exposure_percentage: float | None
    libyears_curve: tuple[LibyearsPoint, ...]
    findings: tuple[FindingLifecycle, ...]
    findings_by_category: tuple[tuple[str, int], ...]
    findings_by_module: tuple[tuple[str, int], ...]
    findings_by_month: tuple[tuple[str, int], ...]
    mean_time_to_fix_days: float | None
    author_rankings: tuple[AuthorRanking, ...]
    warnings: tuple[str, ...]

from dataclasses import dataclass
from datetime import datetime

from domain.entities.advisory import Advisory
from domain.entities.severity import Severity


@dataclass(frozen=True)
class PatchLagRecord:
    advisory: Advisory
    lockfile_path: str
    vulnerable_version: str
    exposure_started_at: datetime
    exposure_start_commit_sha: str
    reference_at: datetime
    fixed_version: str | None
    fix_commit_sha: str | None
    fixed_at: datetime | None
    lag_days: float | None
    fixed_before_disclosure: bool = False

    @property
    def is_open(self) -> bool:
        return self.fix_commit_sha is None

    @property
    def severity(self) -> Severity:
        return self.advisory.severity

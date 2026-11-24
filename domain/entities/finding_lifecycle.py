from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from domain.entities.author import Author
from domain.entities.severity import Severity

SECONDS_PER_DAY = 86400


class FindingKind(StrEnum):
    SECRET = "secret"
    INSECURE_PATTERN = "insecure_pattern"


@dataclass(frozen=True)
class FindingLifecycle:
    fingerprint: str
    kind: FindingKind
    rule_id: str
    category: str
    severity: Severity
    file_path: str
    module: str
    introduced_commit_sha: str
    introduced_at: datetime
    fixed_commit_sha: str | None
    fixed_at: datetime | None
    last_seen_line: int
    introduced_by: Author | None = None

    @property
    def is_open(self) -> bool:
        return self.fixed_at is None

    def lifetime_days(self, as_of: datetime) -> float:
        end = self.fixed_at if self.fixed_at is not None else as_of
        return (end - self.introduced_at).total_seconds() / SECONDS_PER_DAY

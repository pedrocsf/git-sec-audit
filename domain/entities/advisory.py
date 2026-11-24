from dataclasses import dataclass
from datetime import datetime

from domain.entities.severity import Severity

CVE_PREFIX = "CVE-"


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    aliases: tuple[str, ...]
    ecosystem: str
    package: str
    summary: str
    severity: Severity
    published_at: datetime
    fixed_versions: tuple[str, ...]

    @property
    def display_id(self) -> str:
        for alias in self.aliases:
            if alias.startswith(CVE_PREFIX):
                return alias
        return self.advisory_id

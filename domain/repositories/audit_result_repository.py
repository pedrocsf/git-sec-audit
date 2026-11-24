from abc import ABC, abstractmethod

from domain.entities.commit import Commit
from domain.entities.dependency_version import DependencyVersion
from domain.entities.finding_lifecycle import FindingLifecycle
from domain.entities.insecure_pattern_finding import (
    InsecurePatternFinding,
    PatternMatch,
)
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.secret_finding import SecretFinding


class AuditResultRepository(ABC):
    @abstractmethod
    def save_commits(self, commits: list[Commit]) -> None:
        ...

    @abstractmethod
    def load_commits(self) -> list[Commit]:
        ...

    @abstractmethod
    def save_dependency_versions(self, versions: list[DependencyVersion]) -> None:
        ...

    @abstractmethod
    def load_dependency_versions(self) -> list[DependencyVersion]:
        ...

    @abstractmethod
    def save_patch_lag_records(self, records: list[PatchLagRecord]) -> None:
        ...

    @abstractmethod
    def load_patch_lag_records(self) -> list[PatchLagRecord]:
        ...

    @abstractmethod
    def save_libyears_points(self, points: list[LibyearsPoint]) -> None:
        ...

    @abstractmethod
    def load_libyears_points(self) -> list[LibyearsPoint]:
        ...

    @abstractmethod
    def save_secret_findings(self, findings: list[SecretFinding]) -> None:
        ...

    @abstractmethod
    def load_secret_findings(self) -> list[SecretFinding]:
        ...

    @abstractmethod
    def save_pattern_findings(self, findings: list[InsecurePatternFinding]) -> None:
        ...

    @abstractmethod
    def load_pattern_findings(self) -> list[InsecurePatternFinding]:
        ...

    @abstractmethod
    def save_finding_lifecycles(self, lifecycles: list[FindingLifecycle]) -> None:
        ...

    @abstractmethod
    def load_finding_lifecycles(self) -> list[FindingLifecycle]:
        ...

    @abstractmethod
    def find_blob_matches(
        self, scanner_id: str, blob_sha: str
    ) -> list[PatternMatch] | None:
        ...

    @abstractmethod
    def save_blob_matches(
        self, scanner_id: str, blob_sha: str, matches: list[PatternMatch]
    ) -> None:
        ...

    @abstractmethod
    def save_run_metadata(self, key: str, value: str) -> None:
        ...

    @abstractmethod
    def load_run_metadata(self, key: str) -> str | None:
        ...

    @abstractmethod
    def load_run_metadata_by_prefix(self, prefix: str) -> dict[str, str]:
        ...

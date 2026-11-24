import hashlib
from dataclasses import replace

from domain.entities.commit import Commit
from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.insecure_pattern_finding import (
    FINGERPRINT_SEPARATOR,
    InsecurePatternFinding,
)
from domain.entities.module_path import resolve_module
from domain.entities.secret_finding import SecretFinding
from domain.entities.severity import Severity
from domain.repositories.audit_result_repository import AuditResultRepository

SECRET_CATEGORY = "secret"
SECRET_SEVERITY = Severity.HIGH


class TrackFindingLifecycle:
    def __init__(self, audit_result_repository: AuditResultRepository) -> None:
        self._audit_result_repository = audit_result_repository

    def execute(self) -> list[FindingLifecycle]:
        lifecycles = self._track_patterns() + self._track_secrets()
        self._audit_result_repository.save_finding_lifecycles(lifecycles)
        return lifecycles

    def _track_patterns(self) -> list[FindingLifecycle]:
        findings_by_location = self._index_pattern_findings()
        lifecycles: list[FindingLifecycle] = []
        open_by_path: dict[str, dict[str, int]] = {}
        for commit in self._audit_result_repository.load_commits():
            for change in commit.file_changes:
                current = {}
                if change.new_blob_sha is not None:
                    current = findings_by_location.get((commit.sha, change.path), {})
                open_by_path.setdefault(change.path, {})
                self._apply_change(commit, current, open_by_path[change.path], lifecycles)
        return lifecycles

    def _index_pattern_findings(
        self,
    ) -> dict[tuple[str, str], dict[str, InsecurePatternFinding]]:
        index: dict[tuple[str, str], dict[str, InsecurePatternFinding]] = {}
        for finding in self._audit_result_repository.load_pattern_findings():
            location = index.setdefault((finding.commit_sha, finding.file_path), {})
            location.setdefault(finding.fingerprint, finding)
        return index

    def _apply_change(
        self,
        commit: Commit,
        current: dict[str, InsecurePatternFinding],
        open_indexes: dict[str, int],
        lifecycles: list[FindingLifecycle],
    ) -> None:
        for fingerprint in list(open_indexes):
            if fingerprint in current:
                continue
            index = open_indexes.pop(fingerprint)
            lifecycles[index] = replace(
                lifecycles[index],
                fixed_commit_sha=commit.sha,
                fixed_at=commit.committed_at,
            )
        for fingerprint, finding in current.items():
            if fingerprint in open_indexes:
                index = open_indexes[fingerprint]
                lifecycles[index] = replace(lifecycles[index], last_seen_line=finding.line)
                continue
            open_indexes[fingerprint] = len(lifecycles)
            lifecycles.append(self._open_pattern_lifecycle(commit, finding))

    def _open_pattern_lifecycle(
        self, commit: Commit, finding: InsecurePatternFinding
    ) -> FindingLifecycle:
        return FindingLifecycle(
            fingerprint=finding.fingerprint,
            kind=FindingKind.INSECURE_PATTERN,
            rule_id=finding.rule_id,
            category=finding.category,
            severity=finding.severity,
            file_path=finding.file_path,
            module=finding.module,
            introduced_commit_sha=commit.sha,
            introduced_at=commit.committed_at,
            fixed_commit_sha=None,
            fixed_at=None,
            last_seen_line=finding.line,
        )

    def _track_secrets(self) -> list[FindingLifecycle]:
        groups: dict[tuple[str, str], list[SecretFinding]] = {}
        for finding in self._audit_result_repository.load_secret_findings():
            groups.setdefault((finding.secret_hash, finding.file_path), []).append(finding)
        return [self._build_secret_lifecycle(group) for group in groups.values()]

    def _build_secret_lifecycle(self, group: list[SecretFinding]) -> FindingLifecycle:
        oldest = min(group, key=lambda finding: finding.committed_at)
        still_in_head = any(finding.still_in_head for finding in group)
        fixed_commit_sha = None if still_in_head else oldest.removed_commit_sha
        fixed_at = None if still_in_head else oldest.removed_at
        return FindingLifecycle(
            fingerprint=self._secret_fingerprint(oldest),
            kind=FindingKind.SECRET,
            rule_id=oldest.rule_id,
            category=SECRET_CATEGORY,
            severity=SECRET_SEVERITY,
            file_path=oldest.file_path,
            module=resolve_module(oldest.file_path),
            introduced_commit_sha=oldest.commit_sha,
            introduced_at=oldest.committed_at,
            fixed_commit_sha=fixed_commit_sha,
            fixed_at=fixed_at,
            last_seen_line=self._secret_last_seen_line(oldest, group),
            introduced_by=oldest.author,
        )

    def _secret_last_seen_line(
        self, oldest: SecretFinding, group: list[SecretFinding]
    ) -> int:
        for finding in group:
            if finding.still_in_head and finding.head_line:
                return finding.head_line
        return oldest.line

    def _secret_fingerprint(self, finding: SecretFinding) -> str:
        raw = FINGERPRINT_SEPARATOR.join(
            (SECRET_CATEGORY, finding.secret_hash, finding.file_path)
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

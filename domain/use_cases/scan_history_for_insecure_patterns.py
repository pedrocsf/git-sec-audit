from dataclasses import dataclass

from domain.entities.commit import Commit
from domain.entities.insecure_pattern_finding import (
    BlobToScan,
    InsecurePatternFinding,
    PatternMatch,
    build_pattern_fingerprint,
)
from domain.entities.module_path import resolve_module
from domain.errors import GitSecAuditError, ScannerUnavailableError
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.git_history_repository import GitHistoryRepository
from domain.repositories.pattern_scanner_repository import PatternScannerRepository
from domain.repositories.resource_monitor import ResourceMonitor

DEFAULT_BATCH_SIZE = 200
DEFAULT_MAX_BLOB_BYTES = 1_000_000
DISK_BYTES_FACTOR = 2
MEMORY_BYTES_FACTOR = 4
PATTERN_WARNING_PREFIX = "warning.patterns."
NO_COMMITS_MESSAGE = "Nenhum commit sincronizado; execute a sincronização do histórico primeiro"


@dataclass(frozen=True)
class ScanHistoryForInsecurePatternsRequest:
    batch_size: int = DEFAULT_BATCH_SIZE
    max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES


@dataclass(frozen=True)
class BlobOccurrence:
    commit: Commit
    path: str
    blob_sha: str


class ScanHistoryForInsecurePatterns:
    def __init__(
        self,
        git_history_repository: GitHistoryRepository,
        pattern_scanners: list[PatternScannerRepository],
        audit_result_repository: AuditResultRepository,
        resource_monitor: ResourceMonitor,
    ) -> None:
        self._git_history_repository = git_history_repository
        self._pattern_scanners = pattern_scanners
        self._audit_result_repository = audit_result_repository
        self._resource_monitor = resource_monitor

    def execute(
        self, request: ScanHistoryForInsecurePatternsRequest
    ) -> list[InsecurePatternFinding]:
        commits = self._audit_result_repository.load_commits()
        if not commits:
            raise GitSecAuditError(NO_COMMITS_MESSAGE)
        findings: list[InsecurePatternFinding] = []
        for scanner in self._pattern_scanners:
            findings.extend(self._scan_with(scanner, commits, request))
        self._audit_result_repository.save_pattern_findings(findings)
        return findings

    def _scan_with(
        self,
        scanner: PatternScannerRepository,
        commits: list[Commit],
        request: ScanHistoryForInsecurePatternsRequest,
    ) -> list[InsecurePatternFinding]:
        occurrences = self._collect_occurrences(scanner, commits)
        try:
            matches_by_blob = self._resolve_matches(scanner, occurrences, request)
        except ScannerUnavailableError as error:
            key = PATTERN_WARNING_PREFIX + scanner.scanner_id
            self._audit_result_repository.save_run_metadata(key, str(error))
            return []
        return self._build_findings(occurrences, matches_by_blob)

    def _collect_occurrences(
        self, scanner: PatternScannerRepository, commits: list[Commit]
    ) -> list[BlobOccurrence]:
        occurrences = []
        for commit in commits:
            for change in commit.file_changes:
                if change.new_blob_sha is None or not scanner.supports(change.path):
                    continue
                occurrences.append(BlobOccurrence(commit, change.path, change.new_blob_sha))
        return occurrences

    def _resolve_matches(
        self,
        scanner: PatternScannerRepository,
        occurrences: list[BlobOccurrence],
        request: ScanHistoryForInsecurePatternsRequest,
    ) -> dict[str, list[PatternMatch]]:
        matches_by_blob: dict[str, list[PatternMatch]] = {}
        pending: dict[str, str] = {}
        for occurrence in occurrences:
            if occurrence.blob_sha in matches_by_blob or occurrence.blob_sha in pending:
                continue
            cached = self._audit_result_repository.find_blob_matches(
                scanner.scanner_id, occurrence.blob_sha
            )
            if cached is None:
                pending[occurrence.blob_sha] = occurrence.path
                continue
            matches_by_blob[occurrence.blob_sha] = cached
        items = list(pending.items())
        for start in range(0, len(items), request.batch_size):
            batch = items[start : start + request.batch_size]
            matches_by_blob.update(self._scan_batch(scanner, batch, request.max_blob_bytes))
        return matches_by_blob

    def _scan_batch(
        self,
        scanner: PatternScannerRepository,
        batch: list[tuple[str, str]],
        max_blob_bytes: int,
    ) -> dict[str, list[PatternMatch]]:
        results: dict[str, list[PatternMatch]] = {}
        blobs = []
        for blob_sha, path in batch:
            content = self._git_history_repository.read_blob(blob_sha)
            if len(content) > max_blob_bytes:
                results[blob_sha] = []
                continue
            blobs.append(BlobToScan(blob_sha, path, content))
        if blobs:
            batch_bytes = sum(len(blob.content) for blob in blobs)
            self._resource_monitor.ensure_capacity(
                DISK_BYTES_FACTOR * batch_bytes, MEMORY_BYTES_FACTOR * batch_bytes
            )
            scanned = scanner.scan_blobs(blobs)
            for blob in blobs:
                results[blob.blob_sha] = scanned.get(blob.blob_sha, [])
        for blob_sha, matches in results.items():
            self._audit_result_repository.save_blob_matches(scanner.scanner_id, blob_sha, matches)
        return results

    def _build_findings(
        self,
        occurrences: list[BlobOccurrence],
        matches_by_blob: dict[str, list[PatternMatch]],
    ) -> list[InsecurePatternFinding]:
        findings = []
        for occurrence in occurrences:
            for match in matches_by_blob.get(occurrence.blob_sha, []):
                findings.append(self._build_finding(occurrence, match))
        return findings

    def _build_finding(
        self, occurrence: BlobOccurrence, match: PatternMatch
    ) -> InsecurePatternFinding:
        return InsecurePatternFinding(
            fingerprint=build_pattern_fingerprint(
                match.rule_id, occurrence.path, match.line_content
            ),
            rule_id=match.rule_id,
            category=match.category,
            severity=match.severity,
            file_path=occurrence.path,
            module=resolve_module(occurrence.path),
            line=match.line,
            commit_sha=occurrence.commit.sha,
            committed_at=occurrence.commit.committed_at,
            blob_sha=occurrence.blob_sha,
            message=match.message,
        )

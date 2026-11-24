from datetime import datetime, timezone

from domain.entities.author import Author
from domain.entities.secret_finding import SecretFinding
from domain.errors import ScannerUnavailableError
from domain.use_cases.scan_history_for_secrets import (
    ScanHistoryForSecrets,
    ScanHistoryForSecretsRequest,
)
from tests.fakes.fake_secret_scanner import FakeSecretScanner
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository


def build_finding():
    return SecretFinding(
        fingerprint="fp",
        rule_id="rule",
        secret_hash="hash",
        file_path="a.py",
        commit_sha="c1",
        committed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        line=1,
        author=Author("Ana", "ana@x.com"),
        still_in_head=True,
        head_line=1,
        removed_commit_sha=None,
        removed_at=None,
    )


def test_saves_and_returns_findings():
    repository = InMemoryAuditResultRepository()
    finding = build_finding()
    use_case = ScanHistoryForSecrets(FakeSecretScanner(findings=[finding]), repository)
    result = use_case.execute(ScanHistoryForSecretsRequest(branch="main"))
    assert result == [finding]
    assert repository.load_secret_findings() == [finding]


def test_scanner_unavailable_records_warning_and_returns_empty():
    repository = InMemoryAuditResultRepository()
    scanner = FakeSecretScanner(error=ScannerUnavailableError("gitleaks missing"))
    result = ScanHistoryForSecrets(scanner, repository).execute(
        ScanHistoryForSecretsRequest(branch="main")
    )
    assert result == []
    assert repository.load_secret_findings() == []
    assert repository.load_run_metadata("warning.secrets") == "gitleaks missing"

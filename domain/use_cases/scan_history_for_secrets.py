from dataclasses import dataclass

from domain.entities.secret_finding import SecretFinding
from domain.errors import ScannerUnavailableError
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.secret_scanner_repository import SecretScannerRepository

SECRETS_WARNING_KEY = "warning.secrets"


@dataclass(frozen=True)
class ScanHistoryForSecretsRequest:
    branch: str


class ScanHistoryForSecrets:
    def __init__(
        self,
        secret_scanner_repository: SecretScannerRepository,
        audit_result_repository: AuditResultRepository,
    ) -> None:
        self._secret_scanner_repository = secret_scanner_repository
        self._audit_result_repository = audit_result_repository

    def execute(self, request: ScanHistoryForSecretsRequest) -> list[SecretFinding]:
        try:
            findings = self._secret_scanner_repository.scan_history(request.branch)
        except ScannerUnavailableError as error:
            self._audit_result_repository.save_run_metadata(SECRETS_WARNING_KEY, str(error))
            self._audit_result_repository.save_secret_findings([])
            return []
        self._audit_result_repository.save_secret_findings(findings)
        return findings

from domain.repositories.secret_scanner_repository import SecretScannerRepository


class FakeSecretScanner(SecretScannerRepository):
    def __init__(self, findings=None, error=None):
        self._findings = list(findings or [])
        self._error = error

    def scan_history(self, branch):
        if self._error is not None:
            raise self._error
        return list(self._findings)

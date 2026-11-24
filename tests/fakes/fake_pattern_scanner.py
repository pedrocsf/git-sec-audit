from domain.repositories.pattern_scanner_repository import PatternScannerRepository


class FakePatternScanner(PatternScannerRepository):
    def __init__(self, scanner_id="fake", supported_suffixes=(".dart",), matches_by_blob=None, error=None):
        self._scanner_id = scanner_id
        self._supported_suffixes = tuple(supported_suffixes)
        self._matches_by_blob = dict(matches_by_blob or {})
        self._error = error
        self.scanned_batches = []

    @property
    def scanner_id(self):
        return self._scanner_id

    def supports(self, path):
        return path.endswith(self._supported_suffixes)

    def scan_blobs(self, blobs):
        if self._error is not None:
            raise self._error
        self.scanned_batches.append([blob.blob_sha for blob in blobs])
        return {
            blob.blob_sha: list(self._matches_by_blob.get(blob.blob_sha, []))
            for blob in blobs
        }

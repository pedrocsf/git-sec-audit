from domain.repositories.audit_result_repository import AuditResultRepository


class InMemoryAuditResultRepository(AuditResultRepository):
    def __init__(self) -> None:
        self._commits = []
        self._dependency_versions = []
        self._patch_lag_records = []
        self._libyears_points = []
        self._secret_findings = []
        self._pattern_findings = []
        self._finding_lifecycles = []
        self._blob_matches = {}
        self._run_metadata = {}

    def save_commits(self, commits):
        self._commits = list(commits)

    def load_commits(self):
        return list(self._commits)

    def save_dependency_versions(self, versions):
        self._dependency_versions = list(versions)

    def load_dependency_versions(self):
        return list(self._dependency_versions)

    def save_patch_lag_records(self, records):
        self._patch_lag_records = list(records)

    def load_patch_lag_records(self):
        return list(self._patch_lag_records)

    def save_libyears_points(self, points):
        self._libyears_points = list(points)

    def load_libyears_points(self):
        return list(self._libyears_points)

    def save_secret_findings(self, findings):
        self._secret_findings = list(findings)

    def load_secret_findings(self):
        return list(self._secret_findings)

    def save_pattern_findings(self, findings):
        self._pattern_findings = list(findings)

    def load_pattern_findings(self):
        return list(self._pattern_findings)

    def save_finding_lifecycles(self, lifecycles):
        self._finding_lifecycles = list(lifecycles)

    def load_finding_lifecycles(self):
        return list(self._finding_lifecycles)

    def find_blob_matches(self, scanner_id, blob_sha):
        matches = self._blob_matches.get((scanner_id, blob_sha))
        if matches is None:
            return None
        return list(matches)

    def save_blob_matches(self, scanner_id, blob_sha, matches):
        self._blob_matches[(scanner_id, blob_sha)] = list(matches)

    def save_run_metadata(self, key, value):
        self._run_metadata[key] = value

    def load_run_metadata(self, key):
        return self._run_metadata.get(key)

    def load_run_metadata_by_prefix(self, prefix):
        return {
            key: value
            for key, value in self._run_metadata.items()
            if key.startswith(prefix)
        }

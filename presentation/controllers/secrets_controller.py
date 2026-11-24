from domain.entities.finding_lifecycle import FindingKind
from domain.use_cases.attribute_finding_to_author import (
    AttributeFindingToAuthorRequest,
)
from domain.use_cases.scan_history_for_secrets import ScanHistoryForSecretsRequest
from domain.use_cases.sync_commit_history import SyncCommitHistoryRequest


class SecretsController:
    def __init__(
        self,
        sync_commit_history,
        scan_history_for_secrets,
        track_finding_lifecycle,
        attribute_finding_to_author,
        console_view,
    ):
        self._sync_commit_history = sync_commit_history
        self._scan_history_for_secrets = scan_history_for_secrets
        self._track_finding_lifecycle = track_finding_lifecycle
        self._attribute_finding_to_author = attribute_finding_to_author
        self._console_view = console_view

    def run(self, options):
        self._sync_commit_history.execute(
            SyncCommitHistoryRequest(
                options.repository_name, options.branch, options.first_parent
            )
        )
        findings = self._scan_history_for_secrets.execute(
            ScanHistoryForSecretsRequest(options.branch)
        )
        self._console_view.render_secret_findings(findings)
        self._track_finding_lifecycle.execute()
        lifecycles = self._attribute_finding_to_author.execute(
            AttributeFindingToAuthorRequest(
                options.head_revision, options.ignore_revs_file
            )
        )
        secret_lifecycles = [
            lifecycle for lifecycle in lifecycles if lifecycle.kind == FindingKind.SECRET
        ]
        self._console_view.render_lifecycles(secret_lifecycles, options.as_of)

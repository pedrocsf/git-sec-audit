from domain.entities.finding_lifecycle import FindingKind
from domain.use_cases.attribute_finding_to_author import (
    AttributeFindingToAuthorRequest,
)
from domain.use_cases.scan_history_for_insecure_patterns import (
    ScanHistoryForInsecurePatternsRequest,
)
from domain.use_cases.sync_commit_history import SyncCommitHistoryRequest


class PatternsController:
    def __init__(
        self,
        sync_commit_history,
        scan_history_for_insecure_patterns,
        track_finding_lifecycle,
        attribute_finding_to_author,
        console_view,
    ):
        self._sync_commit_history = sync_commit_history
        self._scan_history_for_insecure_patterns = scan_history_for_insecure_patterns
        self._track_finding_lifecycle = track_finding_lifecycle
        self._attribute_finding_to_author = attribute_finding_to_author
        self._console_view = console_view

    def run(self, options):
        self._sync_commit_history.execute(
            SyncCommitHistoryRequest(
                options.repository_name, options.branch, options.first_parent
            )
        )
        findings = self._scan_history_for_insecure_patterns.execute(
            ScanHistoryForInsecurePatternsRequest()
        )
        self._console_view.render_pattern_findings(findings)
        self._track_finding_lifecycle.execute()
        lifecycles = self._attribute_finding_to_author.execute(
            AttributeFindingToAuthorRequest(
                options.head_revision, options.ignore_revs_file
            )
        )
        pattern_lifecycles = [
            lifecycle
            for lifecycle in lifecycles
            if lifecycle.kind == FindingKind.INSECURE_PATTERN
        ]
        self._console_view.render_lifecycles(pattern_lifecycles, options.as_of)

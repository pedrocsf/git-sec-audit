from domain.use_cases.calculate_libyears import CalculateLibyearsRequest
from domain.use_cases.calculate_patch_lag import CalculatePatchLagRequest
from domain.use_cases.extract_dependency_timeline import (
    ExtractDependencyTimelineRequest,
)
from domain.use_cases.sync_commit_history import SyncCommitHistoryRequest


class PatchLagController:
    def __init__(
        self,
        sync_commit_history,
        extract_dependency_timeline,
        calculate_patch_lag,
        calculate_libyears,
        console_view,
    ):
        self._sync_commit_history = sync_commit_history
        self._extract_dependency_timeline = extract_dependency_timeline
        self._calculate_patch_lag = calculate_patch_lag
        self._calculate_libyears = calculate_libyears
        self._console_view = console_view

    def run(self, options):
        self._sync_commit_history.execute(
            SyncCommitHistoryRequest(
                options.repository_name, options.branch, options.first_parent
            )
        )
        versions = self._extract_dependency_timeline.execute(
            ExtractDependencyTimelineRequest(options.branch, options.first_parent)
        )
        self._console_view.render_dependency_timeline(versions)
        records = self._calculate_patch_lag.execute(
            CalculatePatchLagRequest(options.as_of)
        )
        points = self._calculate_libyears.execute(
            CalculateLibyearsRequest(options.as_of)
        )
        self._console_view.render_patch_lag(records, points)

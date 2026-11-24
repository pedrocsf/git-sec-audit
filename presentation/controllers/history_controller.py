from domain.use_cases.sync_commit_history import SyncCommitHistoryRequest


class HistoryController:
    def __init__(self, sync_commit_history, console_view):
        self._sync_commit_history = sync_commit_history
        self._console_view = console_view

    def run(self, repository_name, branch, first_parent):
        commits = self._sync_commit_history.execute(
            SyncCommitHistoryRequest(repository_name, branch, first_parent)
        )
        self._console_view.render_commits(commits)

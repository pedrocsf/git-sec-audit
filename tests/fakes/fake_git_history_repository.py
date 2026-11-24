from domain.repositories.git_history_repository import GitHistoryRepository


class FakeGitHistoryRepository(GitHistoryRepository):
    def __init__(self, commits=None, files=None, blobs=None, blame=None, head_sha=None):
        self._commits = list(commits or [])
        self._files = dict(files or {})
        self._blobs = dict(blobs or {})
        self._blame = dict(blame or {})
        self._head_sha = head_sha

    def list_commits(self, branch, first_parent, paths=()):
        if not paths:
            return list(self._commits)
        result = []
        for commit in self._commits:
            changes = tuple(c for c in commit.file_changes if c.path in paths)
            if not changes:
                continue
            result.append(
                type(commit)(
                    sha=commit.sha,
                    author=commit.author,
                    authored_at=commit.authored_at,
                    committed_at=commit.committed_at,
                    parent_shas=commit.parent_shas,
                    subject=commit.subject,
                    file_changes=changes,
                )
            )
        return result

    def resolve_commit(self, revision):
        if self._head_sha is not None:
            return self._head_sha
        if self._commits:
            return self._commits[-1].sha
        return revision

    def read_file_at(self, commit_sha, path):
        return self._files.get((commit_sha, path))

    def read_blob(self, blob_sha):
        return self._blobs[blob_sha]

    def find_paths_in_history(self, branch, file_names):
        paths = set()
        for commit in self._commits:
            for change in commit.file_changes:
                if change.path.rsplit("/", 1)[-1] in file_names:
                    paths.add(change.path)
        return sorted(paths)

    def blame_line(self, commit_sha, path, line, ignore_revs_file):
        return self._blame.get((commit_sha, path, line))

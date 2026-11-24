from dataclasses import dataclass
from datetime import datetime

from domain.entities.commit import Commit, FileChangeStatus
from domain.entities.dependency_version import DependencyVersion
from domain.errors import LockfileParseError
from domain.repositories.audit_result_repository import AuditResultRepository
from domain.repositories.git_history_repository import GitHistoryRepository
from domain.repositories.lockfile_parser import LockfileParser
from domain.repositories.resource_monitor import ResourceMonitor

LOCKFILE_NAMES = ("pubspec.lock", "package-lock.json")
MANIFEST_FALLBACKS = {"pubspec.lock": "pubspec.yaml"}
IGNORED_PATH_SEGMENTS = (
    "node_modules",
    ".dart_tool",
    "build",
    ".symlinks",
    "ephemeral",
    ".pub-cache",
)
REQUIRED_DISK_BYTES = 50 * 1024 * 1024
REQUIRED_MEMORY_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class ExtractDependencyTimelineRequest:
    branch: str
    first_parent: bool


class ExtractDependencyTimeline:
    def __init__(
        self,
        git_history_repository: GitHistoryRepository,
        lockfile_parsers: list[LockfileParser],
        audit_result_repository: AuditResultRepository,
        resource_monitor: ResourceMonitor,
    ) -> None:
        self._git_history_repository = git_history_repository
        self._lockfile_parsers = lockfile_parsers
        self._audit_result_repository = audit_result_repository
        self._resource_monitor = resource_monitor

    def execute(self, request: ExtractDependencyTimelineRequest) -> list[DependencyVersion]:
        self._resource_monitor.ensure_capacity(REQUIRED_DISK_BYTES, REQUIRED_MEMORY_BYTES)
        paths = self._git_history_repository.find_paths_in_history(
            request.branch, LOCKFILE_NAMES
        )
        versions: list[DependencyVersion] = []
        for path in paths:
            if _is_ignored(path):
                continue
            versions.extend(self._extract_path(request, path))
        self._audit_result_repository.save_dependency_versions(versions)
        return versions

    def _find_parser(self, path: str) -> LockfileParser | None:
        for parser in self._lockfile_parsers:
            if parser.supports(path):
                return parser
        return None

    def _extract_path(
        self, request: ExtractDependencyTimelineRequest, path: str
    ) -> list[DependencyVersion]:
        parser = self._find_parser(path)
        if parser is None:
            return []
        commits = self._git_history_repository.list_commits(
            request.branch, request.first_parent, paths=(path,)
        )
        versions = self._track(commits, path, parser, approximated=False)
        if not commits:
            return versions
        return self._approximate_from_manifest(request, path, commits[0]) + versions

    def _approximate_from_manifest(
        self, request: ExtractDependencyTimelineRequest, path: str, first_lock_commit: Commit
    ) -> list[DependencyVersion]:
        manifest_name = MANIFEST_FALLBACKS.get(path.rsplit("/", 1)[-1])
        if manifest_name is None:
            return []
        directory, separator, _ = path.rpartition("/")
        manifest_path = f"{directory}{separator}{manifest_name}"
        parser = self._find_parser(manifest_path)
        if parser is None:
            return []
        manifest_commits = [
            commit
            for commit in self._git_history_repository.list_commits(
                request.branch, request.first_parent, paths=(manifest_path,)
            )
            if commit.committed_at < first_lock_commit.committed_at
        ]
        versions = self._track(manifest_commits, manifest_path, parser, approximated=True)
        return [_close_at(version, first_lock_commit) for version in versions]

    def _track(
        self, commits: list[Commit], path: str, parser: LockfileParser, approximated: bool
    ) -> list[DependencyVersion]:
        state: dict[tuple[str, str, str], tuple[str, datetime]] = {}
        closed: list[DependencyVersion] = []
        for commit in commits:
            current = self._read_state(commit, path, parser)
            if current is None:
                continue
            for key in [key for key in state if key not in current]:
                start_sha, start_at = state.pop(key)
                closed.append(
                    _build(key, path, start_sha, start_at, commit, approximated)
                )
            for key in current:
                state.setdefault(key, (commit.sha, commit.committed_at))
        opened = [
            _build(key, path, start_sha, start_at, None, approximated)
            for key, (start_sha, start_at) in state.items()
        ]
        return closed + opened

    def _read_state(
        self, commit: Commit, path: str, parser: LockfileParser
    ) -> set[tuple[str, str, str]] | None:
        change = next((item for item in commit.file_changes if item.path == path), None)
        if change is None:
            return None
        if change.status == FileChangeStatus.DELETED:
            return set()
        content = self._git_history_repository.read_file_at(commit.sha, path)
        if content is None:
            return None
        try:
            packages = parser.parse(content)
        except LockfileParseError:
            return None
        return {(item.ecosystem, item.name, item.version) for item in packages}


def _is_ignored(path: str) -> bool:
    return any(segment in IGNORED_PATH_SEGMENTS for segment in path.split("/"))


def _build(
    key: tuple[str, str, str],
    path: str,
    start_sha: str,
    start_at: datetime,
    end_commit: Commit | None,
    approximated: bool,
) -> DependencyVersion:
    ecosystem, package, version = key
    return DependencyVersion(
        ecosystem=ecosystem,
        package=package,
        version=version,
        lockfile_path=path,
        start_commit_sha=start_sha,
        start_at=start_at,
        end_commit_sha=end_commit.sha if end_commit else None,
        end_at=end_commit.committed_at if end_commit else None,
        approximated=approximated,
    )


def _close_at(version: DependencyVersion, commit: Commit) -> DependencyVersion:
    if version.end_at is not None:
        return version
    return DependencyVersion(
        ecosystem=version.ecosystem,
        package=version.package,
        version=version.version,
        lockfile_path=version.lockfile_path,
        start_commit_sha=version.start_commit_sha,
        start_at=version.start_at,
        end_commit_sha=commit.sha,
        end_at=commit.committed_at,
        approximated=version.approximated,
    )

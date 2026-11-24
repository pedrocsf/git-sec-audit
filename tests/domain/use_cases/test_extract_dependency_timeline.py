from datetime import datetime, timezone

import pytest

from domain.entities.author import Author
from domain.entities.commit import Commit, FileChange, FileChangeStatus
from domain.entities.dependency_version import LockedPackage
from domain.use_cases.extract_dependency_timeline import (
    REQUIRED_DISK_BYTES,
    REQUIRED_MEMORY_BYTES,
    ExtractDependencyTimeline,
    ExtractDependencyTimelineRequest,
)
from tests.fakes.fake_git_history_repository import FakeGitHistoryRepository
from tests.fakes.fake_lockfile_parser import FakeLockfileParser
from tests.fakes.fake_resource_monitor import FakeResourceMonitor
from tests.fakes.in_memory_audit_result_repository import InMemoryAuditResultRepository

LOCK = "pubspec.lock"
MANIFEST = "pubspec.yaml"
REQUEST = ExtractDependencyTimelineRequest("main", True)


def day(number):
    return datetime(2024, 1, number, tzinfo=timezone.utc)


def commit(sha, number, path, status=FileChangeStatus.MODIFIED):
    change = FileChange(path, status, None, None)
    return Commit(sha, Author("Ana", "a@x.com"), day(number), day(number), (), "s", (change,))


def pkg(name, version):
    return LockedPackage("Pub", name, version)


def build(commits, files, contents, monitor=None):
    parser = FakeLockfileParser(("pubspec.lock", "pubspec.yaml", "package-lock.json"), contents)
    results = InMemoryAuditResultRepository()
    monitor = monitor or FakeResourceMonitor()
    use_case = ExtractDependencyTimeline(
        FakeGitHistoryRepository(commits=commits, files=files), [parser], results, monitor
    )
    return use_case, results, monitor


def by_key(versions):
    return {(v.package, v.version): v for v in versions}


def test_added_updated_removed_and_simultaneous_versions():
    commits = [
        commit("c1", 1, LOCK, FileChangeStatus.ADDED),
        commit("c2", 2, LOCK),
        commit("c3", 3, LOCK),
    ]
    files = {("c1", LOCK): "1", ("c2", LOCK): "2", ("c3", LOCK): "3"}
    contents = {
        "1": [pkg("a", "1.0.0"), pkg("b", "1.0.0")],
        "2": [pkg("a", "1.1.0"), pkg("b", "1.0.0"), pkg("b", "2.0.0")],
        "3": [pkg("a", "1.1.0"), pkg("b", "2.0.0")],
    }
    use_case, results, monitor = build(commits, files, contents)

    versions = by_key(use_case.execute(REQUEST))

    assert len(versions) == 4
    assert versions[("a", "1.0.0")].start_at == day(1)
    assert versions[("a", "1.0.0")].end_at == day(2)
    assert versions[("a", "1.0.0")].end_commit_sha == "c2"
    assert versions[("a", "1.1.0")].is_current
    assert versions[("b", "1.0.0")].end_at == day(3)
    assert versions[("b", "2.0.0")].start_at == day(2)
    assert versions[("b", "2.0.0")].is_current
    assert not versions[("a", "1.0.0")].approximated
    assert sorted(results.load_dependency_versions(), key=repr) == sorted(
        versions.values(), key=repr
    )
    assert monitor.calls == [(REQUIRED_DISK_BYTES, REQUIRED_MEMORY_BYTES)]


def test_removed_package_is_closed():
    commits = [commit("c1", 1, LOCK), commit("c2", 2, LOCK)]
    files = {("c1", LOCK): "1", ("c2", LOCK): "2"}
    contents = {"1": [pkg("a", "1.0.0"), pkg("b", "1.0.0")], "2": [pkg("a", "1.0.0")]}
    use_case, _, _ = build(commits, files, contents)

    versions = by_key(use_case.execute(REQUEST))

    assert versions[("b", "1.0.0")].end_at == day(2)
    assert versions[("a", "1.0.0")].is_current


def test_deleted_lockfile_closes_everything():
    commits = [commit("c1", 1, LOCK), commit("c2", 5, LOCK, FileChangeStatus.DELETED)]
    files = {("c1", LOCK): "1"}
    use_case, _, _ = build(commits, files, {"1": [pkg("a", "1.0.0")]})

    versions = use_case.execute(REQUEST)

    assert len(versions) == 1
    assert versions[0].end_at == day(5)
    assert versions[0].end_commit_sha == "c2"


def test_parse_error_keeps_previous_state():
    commits = [commit("c1", 1, LOCK), commit("c2", 2, LOCK), commit("c3", 3, LOCK)]
    files = {("c1", LOCK): "1", ("c2", LOCK): "broken", ("c3", LOCK): "3"}
    contents = {"1": [pkg("a", "1.0.0")], "3": [pkg("a", "1.0.0")]}
    use_case, _, _ = build(commits, files, contents)

    versions = use_case.execute(REQUEST)

    assert len(versions) == 1
    assert versions[0].start_at == day(1)
    assert versions[0].is_current


def test_ignored_paths_are_skipped():
    path = "node_modules/dep/package-lock.json"
    commits = [commit("c1", 1, path), commit("c2", 2, LOCK)]
    files = {("c1", path): "1", ("c2", LOCK): "1"}
    use_case, _, _ = build(commits, files, {"1": [pkg("a", "1.0.0")]})

    versions = use_case.execute(REQUEST)

    assert {v.lockfile_path for v in versions} == {LOCK}


def test_manifest_fallback_before_first_lockfile():
    commits = [
        commit("m1", 1, MANIFEST),
        commit("m2", 2, MANIFEST),
        commit("l1", 4, LOCK, FileChangeStatus.ADDED),
    ]
    files = {("m1", MANIFEST): "m1", ("m2", MANIFEST): "m2", ("l1", LOCK): "l1"}
    contents = {
        "m1": [pkg("a", "1.0.0")],
        "m2": [pkg("a", "1.1.0")],
        "l1": [pkg("a", "1.1.5")],
    }
    use_case, _, _ = build(commits, files, contents)

    versions = by_key(use_case.execute(REQUEST))

    assert versions[("a", "1.0.0")].approximated
    assert versions[("a", "1.0.0")].end_at == day(2)
    assert versions[("a", "1.1.0")].approximated
    assert versions[("a", "1.1.0")].end_at == day(4)
    assert versions[("a", "1.1.0")].end_commit_sha == "l1"
    assert not versions[("a", "1.1.5")].approximated
    assert versions[("a", "1.1.5")].is_current


def test_insufficient_resources_abort_before_work():
    from domain.errors import InsufficientResourcesError

    monitor = FakeResourceMonitor(error=InsufficientResourcesError("no"))
    use_case, results, _ = build([], {}, {}, monitor)

    with pytest.raises(InsufficientResourcesError):
        use_case.execute(REQUEST)
    assert results.load_dependency_versions() == []

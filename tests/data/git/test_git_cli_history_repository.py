import os
import subprocess
from datetime import UTC, datetime

import pytest

from data.git.git_cli_history_repository import GitCliHistoryRepository
from data.git.mailmap_author_normalizer import MailmapAuthorNormalizer
from domain.entities.commit import FileChangeStatus
from domain.errors import GitCommandError


def run_git(repo, *arguments, date="2024-01-01T10:00:00+00:00", name="Alice", email="alice@example.com"):
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": name,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": name,
        "GIT_COMMITTER_EMAIL": email,
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def commit_file(repo, path, content, message, date, name="Alice", email="alice@example.com"):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    run_git(repo, "add", "-A", date=date, name=name, email=email)
    run_git(repo, "commit", "-m", message, date=date, name=name, email=email)
    return run_git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    run_git(path, "init", "-b", "main")
    run_git(path, "config", "user.name", "Alice")
    run_git(path, "config", "user.email", "alice@example.com")
    (path / ".mailmap").write_text("Alice Real <alice@example.com> <old@example.com>\n")
    shas = {}
    shas["first"] = commit_file(path, "pubspec.lock", "a\nb\nc\n", "first", "2024-01-01T10:00:00+02:00")
    shas["spaced"] = commit_file(path, "dir with space/ünï.txt", "x\n", "spaced", "2024-01-02T10:00:00+00:00", "Bob", "bob@example.com")
    shas["nested"] = commit_file(path, "sub/pubspec.lock", "n\n", "nested", "2024-01-03T10:00:00+00:00", "Bob", "BOB@example.com")
    run_git(path, "checkout", "-b", "topic", date="2024-01-04T10:00:00+00:00")
    shas["topic"] = commit_file(path, "topic.txt", "t\n", "topic", "2024-01-04T10:00:00+00:00")
    run_git(path, "checkout", "main", date="2024-01-05T10:00:00+00:00")
    shas["main2"] = commit_file(path, "main2.txt", "m\n", "main2", "2024-01-05T10:00:00+00:00")
    run_git(path, "merge", "--no-ff", "topic", "-m", "merge topic", date="2024-01-06T10:00:00+00:00")
    shas["merge"] = run_git(path, "rev-parse", "HEAD")
    (path / "dir with space/ünï.txt").unlink()
    run_git(path, "add", "-A")
    run_git(path, "commit", "-m", "delete", date="2024-01-07T10:00:00+00:00")
    shas["delete"] = run_git(path, "rev-parse", "HEAD")
    run_git(path, "commit", "--allow-empty", "-m", "empty", date="2024-01-08T10:00:00+00:00")
    shas["empty"] = run_git(path, "rev-parse", "HEAD")
    return path, shas


@pytest.fixture
def history(repo):
    repository = GitCliHistoryRepository(str(repo[0]), MailmapAuthorNormalizer())
    yield repository
    repository.close()


def test_list_commits_is_chronological_with_changes(repo, history):
    _, shas = repo
    commits = history.list_commits("main", first_parent=False)
    subjects = [commit.subject for commit in commits]
    assert subjects[0] == "first"
    assert subjects[-1] == "empty"
    assert set(subjects) == {"first", "spaced", "nested", "topic", "main2", "merge topic", "delete", "empty"}
    by_subject = {commit.subject: commit for commit in commits}
    first = by_subject["first"]
    assert first.authored_at == datetime(2024, 1, 1, 8, 0, tzinfo=UTC)
    assert first.authored_at.tzinfo == UTC
    assert first.parent_shas == ()
    assert {change.path for change in first.file_changes} == {"pubspec.lock", ".mailmap"}
    assert all(change.status == FileChangeStatus.ADDED for change in first.file_changes)
    assert all(change.old_blob_sha is None and change.new_blob_sha for change in first.file_changes)


def test_unicode_and_space_path_and_delete(repo, history):
    commits = {commit.subject: commit for commit in history.list_commits("main", False)}
    added = commits["spaced"].file_changes[0]
    assert added.path == "dir with space/ünï.txt"
    deleted = commits["delete"].file_changes[0]
    assert deleted.status == FileChangeStatus.DELETED
    assert deleted.new_blob_sha is None
    assert deleted.old_blob_sha is not None


def test_commit_without_changes_has_no_file_changes(history):
    commits = {commit.subject: commit for commit in history.list_commits("main", False)}
    assert commits["empty"].file_changes == ()


def test_merge_diffs_against_first_parent(repo, history):
    _, shas = repo
    commits = {commit.subject: commit for commit in history.list_commits("main", False)}
    merge = commits["merge topic"]
    assert merge.is_merge
    assert merge.parent_shas == (shas["main2"], shas["topic"])
    assert [change.path for change in merge.file_changes] == ["topic.txt"]


def test_first_parent_skips_topic_commits(history):
    subjects = [commit.subject for commit in history.list_commits("main", True)]
    assert "topic" not in subjects
    assert "merge topic" in subjects


def test_paths_filter(history):
    commits = history.list_commits("main", False, paths=("pubspec.lock",))
    assert [commit.subject for commit in commits] == ["first"]
    assert [change.path for change in commits[0].file_changes] == ["pubspec.lock"]


def test_mailmap_and_normalizer_applied(history):
    commits = {commit.subject: commit for commit in history.list_commits("main", False)}
    assert commits["spaced"].author == commits["nested"].author
    assert commits["spaced"].author.email == "bob@example.com"


def test_resolve_commit(repo, history):
    _, shas = repo
    assert history.resolve_commit("main") == shas["empty"]
    assert history.resolve_commit(shas["first"][:10]) == shas["first"]
    with pytest.raises(GitCommandError):
        history.resolve_commit("does-not-exist")


def test_read_file_at(repo, history):
    _, shas = repo
    assert history.read_file_at(shas["first"], "pubspec.lock") == "a\nb\nc\n"
    assert history.read_file_at(shas["delete"], "dir with space/ünï.txt") is None
    assert history.read_file_at(shas["spaced"], "dir with space/ünï.txt") == "x\n"


def test_read_blob_and_context_manager(repo):
    path, shas = repo
    blob_sha = run_git(path, "rev-parse", f"{shas['first']}:pubspec.lock")
    with GitCliHistoryRepository(str(path), MailmapAuthorNormalizer()) as repository:
        assert repository.read_blob(blob_sha) == b"a\nb\nc\n"
        assert repository.read_blob(blob_sha) == b"a\nb\nc\n"
        with pytest.raises(GitCommandError):
            repository.read_blob("0" * 40)
        assert repository.read_blob(blob_sha) == b"a\nb\nc\n"
    assert repository._blob_process is None


def test_find_paths_in_history_includes_deleted_and_sorted(history):
    assert history.find_paths_in_history("main", ("pubspec.lock",)) == ["pubspec.lock", "sub/pubspec.lock"]
    assert history.find_paths_in_history("main", ("ünï.txt",)) == ["dir with space/ünï.txt"]
    assert history.find_paths_in_history("main", ("nothing.lock",)) == []


def test_blame_line(repo, history):
    _, shas = repo
    result = history.blame_line(shas["empty"], "pubspec.lock", 2, None)
    assert result is not None
    commit_sha, author = result
    assert commit_sha == shas["first"]
    assert author.name == "Alice"
    assert history.blame_line(shas["empty"], "pubspec.lock", 99, None) is None


def test_blame_uses_default_ignore_revs_file(repo, history):
    path, shas = repo
    touched = commit_file(path, "pubspec.lock", "a\nB\nc\n", "touch", "2024-01-09T10:00:00+00:00", "Carol", "carol@example.com")
    assert history.blame_line(touched, "pubspec.lock", 2, None)[0] == touched
    (path / ".git-blame-ignore-revs").write_text(touched + "\n")
    result = history.blame_line(touched, "pubspec.lock", 2, None)
    assert result[0] != touched


def test_git_errors_raise(tmp_path):
    repository = GitCliHistoryRepository(str(tmp_path), MailmapAuthorNormalizer())
    with pytest.raises(GitCommandError):
        repository.list_commits("main", False)
    with pytest.raises(GitCommandError):
        repository.find_paths_in_history("main", ("a",))

import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from data.scanners.gitleaks_secret_scanner import GitleaksSecretScanner
from domain.entities.author import Author
from domain.entities.commit import Commit
from domain.errors import ScannerUnavailableError
from tests.fakes.fake_git_history_repository import FakeGitHistoryRepository

AUTHOR = Author("Dev", "dev@example.com")
KEPT_SECRET = "KEPT-SECRET-VALUE-123"
REMOVED_SECRET = "REMOVED-SECRET-VALUE-456"


def make_commit(sha, day):
    return Commit(
        sha=sha,
        author=AUTHOR,
        authored_at=datetime(2024, 1, day, tzinfo=timezone.utc),
        committed_at=datetime(2024, 1, day, tzinfo=timezone.utc),
        parent_shas=(),
        subject="s",
    )


def report_item(commit, file, secret, line=1):
    return {
        "Commit": commit,
        "File": file,
        "StartLine": line,
        "RuleID": "generic-api-key",
        "Secret": secret,
        "Date": "2024-01-01T10:00:00+02:00",
        "Author": "Dev",
        "Email": "dev@example.com",
    }


def make_runner(payload, returncode=0, stderr=""):
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=json.dumps(payload), stderr=stderr)

    runner.calls = calls
    return runner


def make_history():
    return FakeGitHistoryRepository(
        commits=[make_commit("c1", 1), make_commit("c2", 2), make_commit("c3", 3)],
        files={
            ("c1", "a.env"): f"x\nK={KEPT_SECRET}\n",
            ("c2", "a.env"): f"x\nK={KEPT_SECRET}\n",
            ("c3", "a.env"): f"x\nK={KEPT_SECRET}\n",
            ("c1", "b.env"): f"R={REMOVED_SECRET}\n",
            ("c2", "b.env"): "R=\n",
            ("c3", "b.env"): "R=\n",
        },
        head_sha="c3",
    )


def make_scanner(payload, which=lambda name: "/bin/gitleaks", **runner_kwargs):
    runner = make_runner(payload, **runner_kwargs)
    return GitleaksSecretScanner("/repo", make_history(), runner=runner, which=which), runner


def build_history_with_changes():
    history = make_history()
    from domain.entities.commit import FileChange, FileChangeStatus

    def with_changes(commit, path):
        return Commit(
            sha=commit.sha,
            author=commit.author,
            authored_at=commit.authored_at,
            committed_at=commit.committed_at,
            parent_shas=commit.parent_shas,
            subject=commit.subject,
            file_changes=(FileChange(path, FileChangeStatus.MODIFIED, None, "b"),),
        )

    commits = [with_changes(c, p) for c in (make_commit("c1", 1), make_commit("c2", 2), make_commit("c3", 3)) for p in ("a.env",)]
    commits_b = [with_changes(c, "b.env") for c in (make_commit("c1", 1), make_commit("c2", 2))]
    return FakeGitHistoryRepository(
        commits=commits + commits_b,
        files=history._files,
        head_sha="c3",
    )


def test_parses_kept_and_removed_secrets():
    payload = [report_item("c1", "a.env", KEPT_SECRET, 2), report_item("c1", "b.env", REMOVED_SECRET)]
    runner = make_runner(payload)
    scanner = GitleaksSecretScanner("/repo", build_history_with_changes(), runner=runner, which=lambda n: "x")

    kept, removed = scanner.scan_history("main")

    assert kept.still_in_head is True
    assert kept.head_line == 2
    assert kept.removed_commit_sha is None
    assert removed.still_in_head is False
    assert removed.head_line is None
    assert removed.removed_commit_sha == "c2"
    assert removed.removed_at == datetime(2024, 1, 2, tzinfo=timezone.utc)
    assert kept.committed_at == datetime(2024, 1, 1, 8, tzinfo=timezone.utc)
    assert kept.secret_hash == hashlib.sha256(KEPT_SECRET.encode()).hexdigest()
    expected = hashlib.sha256(f"generic-api-key\x00a.env\x00{kept.secret_hash}".encode()).hexdigest()
    assert kept.fingerprint == expected


def test_secret_value_never_in_findings():
    payload = [report_item("c1", "a.env", KEPT_SECRET), report_item("c1", "b.env", REMOVED_SECRET)]
    scanner, _ = make_scanner(payload)
    findings = scanner.scan_history("main")
    text = repr(findings)
    assert KEPT_SECRET not in text
    assert REMOVED_SECRET not in text
    assert KEPT_SECRET not in repr(vars(scanner))


def test_command_uses_stdout_report():
    scanner, runner = make_scanner([])
    scanner.scan_history("main")
    command = runner.calls[0][0]
    assert command[:3] == ["gitleaks", "git", "/repo"]
    assert "--log-opts=main" in command
    assert command[command.index("--report-path") + 1] == "-"
    assert "--no-banner" in command


def test_missing_binary():
    scanner, _ = make_scanner([], which=lambda name: None)
    with pytest.raises(ScannerUnavailableError):
        scanner.scan_history("main")


def test_execution_error_has_summarized_stderr_without_secret():
    scanner, _ = make_scanner([], returncode=2, stderr="boom " * 100)
    with pytest.raises(ScannerUnavailableError) as error:
        scanner.scan_history("main")
    assert "boom" in str(error.value)
    assert len(str(error.value)) < 300

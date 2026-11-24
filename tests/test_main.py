import os
import subprocess

import pytest

from composition_root import DependencyOverrides
from data.scanners.config_rule_pattern_scanner import ConfigRulePatternScanner
from main import main
from tests.fakes.fake_advisory_repository import FakeAdvisoryRepository
from tests.fakes.fake_package_release_repository import FakePackageReleaseRepository
from tests.fakes.fake_resource_monitor import FakeResourceMonitor
from tests.fakes.fake_secret_scanner import FakeSecretScanner

AS_OF = "2024-06-01T00:00:00+00:00"


def run_git(repo, *arguments, date):
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Alice",
        "GIT_AUTHOR_EMAIL": "alice@example.com",
        "GIT_COMMITTER_NAME": "Alice",
        "GIT_COMMITTER_EMAIL": "alice@example.com",
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    subprocess.run(
        ["git", "-C", str(repo), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )


def commit_file(repo, path, content, date):
    (repo / path).write_text(content, encoding="utf-8")
    run_git(repo, "add", "-A", date=date)
    run_git(repo, "commit", "-m", f"change {path}", date=date)


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "sample"
    repo.mkdir()
    run_git(repo, "init", "-b", "main", date="2024-01-01T10:00:00+00:00")
    commit_file(repo, "readme.md", "hello\n", "2024-01-01T10:00:00+00:00")
    commit_file(repo, "app.js", "eval(userInput)\n", "2024-02-01T10:00:00+00:00")
    commit_file(repo, "app.js", "console.log(1)\n", "2024-03-01T10:00:00+00:00")
    return repo


def build_overrides():
    return DependencyOverrides(
        advisory_repository=FakeAdvisoryRepository(),
        package_release_repository=FakePackageReleaseRepository(),
        secret_scanner_repository=FakeSecretScanner(),
        pattern_scanners=[ConfigRulePatternScanner()],
        resource_monitor=FakeResourceMonitor(),
    )


def test_all_generates_report_files(repository, tmp_path):
    output_dir = tmp_path / "reports"
    exit_code = main(
        [
            "all",
            "--repo",
            str(repository),
            "--db",
            str(tmp_path / "audit.sqlite"),
            "--output-dir",
            str(output_dir),
            "--as-of",
            AS_OF,
            "--include-authors",
        ],
        build_overrides(),
    )
    assert exit_code == 0
    assert (output_dir / "report.html").exists()
    assert (output_dir / "report.json").exists()
    assert list(output_dir.glob("*.csv"))


def test_history_returns_zero(repository, tmp_path):
    exit_code = main(
        ["history", "--repo", str(repository), "--db", str(tmp_path / "a.sqlite")],
        build_overrides(),
    )
    assert exit_code == 0


def test_invalid_repo_returns_one(tmp_path):
    exit_code = main(
        ["history", "--repo", str(tmp_path / "missing"), "--db", str(tmp_path / "a.sqlite")],
        build_overrides(),
    )
    assert exit_code == 1

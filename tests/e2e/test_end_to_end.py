import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from composition_root import DependencyOverrides
from data.scanners.config_rule_pattern_scanner import ConfigRulePatternScanner
from data.scanners.gitleaks_secret_scanner import GitleaksSecretScanner
from data.scanners.semgrep_pattern_scanner import SemgrepPatternScanner
from data.storage.sqlite_audit_result_repository import SqliteAuditResultRepository
from domain.entities.advisory import Advisory
from domain.entities.author import Author
from domain.entities.ecosystem import PUB_ECOSYSTEM
from domain.entities.package_release import PackageRelease
from domain.entities.secret_finding import SecretFinding
from domain.entities.severity import Severity
from main import main
from tests.fakes.fake_advisory_repository import FakeAdvisoryRepository
from tests.fakes.fake_package_release_repository import FakePackageReleaseRepository
from tests.fakes.fake_resource_monitor import FakeResourceMonitor
from tests.fakes.fake_secret_scanner import FakeSecretScanner

AS_OF_TEXT = "2024-06-01T00:00:00+00:00"
AS_OF = datetime(2024, 6, 1, tzinfo=timezone.utc)
SECONDS_PER_DAY = 86400
ALICE_NAME = "Alice Synthetic"
ALICE_EMAIL = "alice@synthetic.test"
ALICE_OLD_EMAIL = "alice.old@synthetic.test"
BOB_NAME = "Bob Synthetic"
BOB_EMAIL = "bob@synthetic.test"
FIRST_COMMIT_DATE = "2024-01-05T09:00:00+00:00"
LOCK_OLD_DATE = "2024-01-10T10:00:00+00:00"
RULES_OPEN_DATE = "2024-02-01T11:00:00+00:00"
MANIFEST_DATE = "2024-02-15T12:00:00+00:00"
LOCK_NEW_DATE = "2024-03-15T10:00:00+00:00"
RULES_FIX_DATE = "2024-04-01T12:00:00+00:00"
ADVISORY_PUBLISHED = datetime(2024, 2, 10, tzinfo=timezone.utc)
RELEASE_DATE = datetime(2024, 2, 20, 6, tzinfo=timezone.utc)
FIX_DATE = datetime(2024, 3, 15, 10, tzinfo=timezone.utc)
PLANTED_SECRET_VALUE = "planted-secret-value-for-test"
AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"

LOCK_TEMPLATE = """packages:
  vuln_pkg:
    dependency: "direct main"
    description:
      name: vuln_pkg
      url: "https://pub.dev"
    source: hosted
    version: "{vuln_version}"
  other_pkg:
    dependency: "direct main"
    description:
      name: other_pkg
      url: "https://pub.dev"
    source: hosted
    version: "2.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"""
RULES_OPEN = "service cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}\n"
RULES_CLOSED = "service cloud.firestore {\n  match /{document=**} {\n    allow read, write: if request.auth != null;\n  }\n}\n"
MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
    '  <application\n'
    '      android:usesCleartextTraffic="true">\n'
    '  </application>\n'
    '</manifest>\n'
)
DART_INSECURE = "void main() {\n  client.badCertificateCallback = (cert, host, port) => true;\n}\n"


def run_git(repo, *arguments, name=ALICE_NAME, email=ALICE_EMAIL, date="2024-01-01T00:00:00+00:00"):
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


def write_file(repo, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def commit_files(repo, files, date, name=ALICE_NAME, email=ALICE_EMAIL):
    for path, content in files.items():
        write_file(repo, path, content)
    run_git(repo, "add", "-A", name=name, email=email, date=date)
    run_git(repo, "commit", "-m", f"update {date}", name=name, email=email, date=date)
    return run_git(repo, "rev-parse", "HEAD")


@pytest.fixture
def synthetic(tmp_path):
    repo = tmp_path / "synthetic"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    shas = {}
    shas["first"] = commit_files(
        repo,
        {
            "README.md": "synthetic\n",
            ".mailmap": f"{ALICE_NAME} <{ALICE_EMAIL}> <{ALICE_OLD_EMAIL}>\n",
        },
        FIRST_COMMIT_DATE,
        email=ALICE_OLD_EMAIL,
    )
    shas["lock_old"] = commit_files(
        repo, {"app/pubspec.lock": LOCK_TEMPLATE.format(vuln_version="1.0.0")}, LOCK_OLD_DATE
    )
    shas["rules_open"] = commit_files(
        repo, {"firestore.rules": RULES_OPEN}, RULES_OPEN_DATE, BOB_NAME, BOB_EMAIL
    )
    shas["manifest"] = commit_files(
        repo,
        {"android/app/src/main/AndroidManifest.xml": MANIFEST, "notes.txt": "notes\n"},
        MANIFEST_DATE,
        email=ALICE_OLD_EMAIL,
    )
    shas["lock_new"] = commit_files(
        repo, {"app/pubspec.lock": LOCK_TEMPLATE.format(vuln_version="1.0.1")}, LOCK_NEW_DATE
    )
    shas["rules_fix"] = commit_files(
        repo, {"firestore.rules": RULES_CLOSED}, RULES_FIX_DATE, BOB_NAME, BOB_EMAIL
    )
    return repo, shas


def build_advisory():
    return Advisory(
        advisory_id="GHSA-xxxx-yyyy-zzzz",
        aliases=("CVE-2024-0001",),
        ecosystem=PUB_ECOSYSTEM,
        package="vuln_pkg",
        summary="Synthetic advisory",
        severity=Severity.CRITICAL,
        published_at=ADVISORY_PUBLISHED,
        fixed_versions=("1.0.1",),
    )


def build_secret_finding(shas):
    secret_hash = hashlib.sha256(PLANTED_SECRET_VALUE.encode()).hexdigest()
    return SecretFinding(
        fingerprint=f"{shas['manifest']}:notes.txt:aws:1",
        rule_id="aws-access-token",
        secret_hash=secret_hash,
        file_path="notes.txt",
        commit_sha=shas["manifest"],
        committed_at=datetime(2024, 2, 15, 12, tzinfo=timezone.utc),
        line=1,
        author=Author(ALICE_NAME, ALICE_EMAIL),
        still_in_head=True,
        head_line=1,
        removed_commit_sha=None,
        removed_at=None,
    )


def build_overrides(shas):
    releases = [
        PackageRelease(PUB_ECOSYSTEM, "vuln_pkg", "1.0.0", datetime(2023, 12, 1, tzinfo=timezone.utc)),
        PackageRelease(PUB_ECOSYSTEM, "vuln_pkg", "1.0.1", RELEASE_DATE),
        PackageRelease(PUB_ECOSYSTEM, "other_pkg", "2.0.0", datetime(2023, 11, 1, tzinfo=timezone.utc)),
    ]
    advisories = {(PUB_ECOSYSTEM, "vuln_pkg", "1.0.0"): [build_advisory()]}
    return DependencyOverrides(
        advisory_repository=FakeAdvisoryRepository(advisories),
        package_release_repository=FakePackageReleaseRepository(releases),
        secret_scanner_repository=FakeSecretScanner([build_secret_finding(shas)]),
        pattern_scanners=[ConfigRulePatternScanner()],
        resource_monitor=FakeResourceMonitor(),
    )


def snapshot_repository(repo):
    return (
        run_git(repo, "rev-parse", "HEAD"),
        run_git(repo, "status", "--porcelain"),
    )


def read_generated_text(output_dir):
    contents = []
    for name in sorted(os.listdir(output_dir)):
        with open(os.path.join(output_dir, name), encoding="utf-8") as handle:
            contents.append(handle.read())
    return "\n".join(contents)


def exposure_percentage():
    window_start = datetime(2024, 1, 5, 9, tzinfo=timezone.utc)
    exposed = (FIX_DATE - ADVISORY_PUBLISHED).total_seconds()
    window = (AS_OF - window_start).total_seconds()
    return round(exposed / window * 100, 2)


def test_all_pipeline_end_to_end(synthetic, tmp_path):
    repo, shas = synthetic
    before = snapshot_repository(repo)
    db_path = tmp_path / "state" / "audit.sqlite"
    output_dir = tmp_path / "reports"
    exit_code = main(
        [
            "all",
            "--repo", str(repo),
            "--db", str(db_path),
            "--output-dir", str(output_dir),
            "--as-of", AS_OF_TEXT,
            "--include-authors",
            "--anonymize-authors",
        ],
        build_overrides(shas),
    )
    assert exit_code == 0

    storage = SqliteAuditResultRepository(str(db_path))
    records = storage.load_patch_lag_records()
    assert len(records) == 1
    record = records[0]
    assert record.advisory.display_id == "CVE-2024-0001"
    assert record.vulnerable_version == "1.0.0"
    assert record.fixed_version == "1.0.1"
    assert record.fix_commit_sha == shas["lock_new"]
    assert record.exposure_start_commit_sha == shas["lock_old"]
    assert record.reference_at == RELEASE_DATE
    assert record.fixed_at == FIX_DATE
    expected_lag = (FIX_DATE - RELEASE_DATE).total_seconds() / SECONDS_PER_DAY
    assert record.lag_days == pytest.approx(expected_lag)
    assert not record.fixed_before_disclosure

    lifecycles = {item.file_path: item for item in storage.load_finding_lifecycles()}
    rules = lifecycles["firestore.rules"]
    assert rules.rule_id == "firebase-rules-allow-all"
    assert rules.introduced_commit_sha == shas["rules_open"]
    assert rules.introduced_at == datetime(2024, 2, 1, 11, tzinfo=timezone.utc)
    assert rules.fixed_commit_sha == shas["rules_fix"]
    assert rules.fixed_at == datetime(2024, 4, 1, 12, tzinfo=timezone.utc)
    manifest = lifecycles["android/app/src/main/AndroidManifest.xml"]
    assert manifest.rule_id == "android-cleartext-traffic"
    assert manifest.is_open
    assert manifest.introduced_commit_sha == shas["manifest"]
    assert manifest.introduced_by.identity == ALICE_EMAIL
    assert manifest.last_seen_line == 3
    secret = lifecycles["notes.txt"]
    assert secret.is_open
    assert secret.introduced_commit_sha == shas["manifest"]
    storage.close()

    with open(output_dir / "report.json", encoding="utf-8") as handle:
        report = json.load(handle)
    assert report["critical_exposure_percentage"] == exposure_percentage()
    assert report["patch_lag_records"][0]["fixed_version"] == "1.0.1"
    labels = [ranking["author_label"] for ranking in report["author_rankings"]]
    assert labels
    assert labels == [f"Autor {index}" for index in range(1, len(labels) + 1)]

    generated = read_generated_text(output_dir)
    for forbidden in (ALICE_NAME, BOB_NAME, ALICE_EMAIL, ALICE_OLD_EMAIL, BOB_EMAIL):
        assert forbidden not in generated
    assert PLANTED_SECRET_VALUE not in generated
    assert PLANTED_SECRET_VALUE not in db_path.read_bytes().decode("latin-1")

    assert snapshot_repository(repo) == before
    assert before[1] == ""


def plant_secret_repository(tmp_path):
    repo = tmp_path / "secret_repo"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    commit_files(repo, {"README.md": "x\n"}, FIRST_COMMIT_DATE)
    commit_files(
        repo,
        {"config/settings.env": f"AWS_ACCESS_KEY_ID={AWS_EXAMPLE_KEY}\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"},
        LOCK_OLD_DATE,
    )
    return repo


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_gitleaks_hides_secret_value(tmp_path):
    repo = plant_secret_repository(tmp_path)
    from data.git.git_cli_history_repository import GitCliHistoryRepository
    from data.git.mailmap_author_normalizer import MailmapAuthorNormalizer

    history = GitCliHistoryRepository(str(repo), MailmapAuthorNormalizer())
    scanner = GitleaksSecretScanner(str(repo), history)
    findings = scanner.scan_history("HEAD")
    history.close()
    assert findings
    expected_hash = hashlib.sha256(AWS_EXAMPLE_KEY.encode()).hexdigest()
    assert expected_hash in {finding.secret_hash for finding in findings}
    assert AWS_EXAMPLE_KEY not in repr(findings)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_real_semgrep_flags_bad_certificate_callback(tmp_path):
    from composition_root import RULES_DIR
    from domain.entities.insecure_pattern_finding import BlobToScan

    scanner = SemgrepPatternScanner(RULES_DIR)
    blob = BlobToScan("blob1", "lib/client.dart", DART_INSECURE.encode())
    result = scanner.scan_blobs([blob])
    assert result["blob1"]
    assert result["blob1"][0].line == 2

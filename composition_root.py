import os
from dataclasses import dataclass, field
from typing import Any

from data.advisories.ecosystem_release_router import EcosystemReleaseRouter
from data.advisories.npm_registry_release_repository import (
    NpmRegistryReleaseRepository,
)
from data.advisories.osv_advisory_repository import OsvAdvisoryRepository
from data.advisories.pub_dev_release_repository import PubDevReleaseRepository
from data.git.git_cli_history_repository import GitCliHistoryRepository
from data.git.mailmap_author_normalizer import MailmapAuthorNormalizer
from data.http.json_http_client import UrllibJsonHttpClient
from data.lockfiles.npm_lock_parser import NpmLockParser
from data.lockfiles.pubspec_lock_parser import PubspecLockParser
from data.lockfiles.pubspec_yaml_parser import PubspecYamlParser
from data.scanners.config_rule_pattern_scanner import ConfigRulePatternScanner
from data.scanners.gitleaks_secret_scanner import GitleaksSecretScanner
from data.scanners.semgrep_pattern_scanner import SemgrepPatternScanner
from data.storage.sqlite_audit_result_repository import SqliteAuditResultRepository
from data.system.proc_resource_monitor import ProcResourceMonitor
from domain.entities.ecosystem import NPM_ECOSYSTEM, PUB_ECOSYSTEM
from domain.use_cases.attribute_finding_to_author import AttributeFindingToAuthor
from domain.use_cases.build_security_report import BuildSecurityReport
from domain.use_cases.calculate_libyears import CalculateLibyears
from domain.use_cases.calculate_patch_lag import CalculatePatchLag
from domain.use_cases.extract_dependency_timeline import ExtractDependencyTimeline
from domain.use_cases.scan_history_for_insecure_patterns import (
    ScanHistoryForInsecurePatterns,
)
from domain.use_cases.scan_history_for_secrets import ScanHistoryForSecrets
from domain.use_cases.sync_commit_history import SyncCommitHistory
from domain.use_cases.track_finding_lifecycle import TrackFindingLifecycle
from presentation.controllers.history_controller import HistoryController
from presentation.controllers.patch_lag_controller import PatchLagController
from presentation.controllers.patterns_controller import PatternsController
from presentation.controllers.report_controller import ReportController
from presentation.controllers.secrets_controller import SecretsController
from presentation.views.console_view import ConsoleView
from presentation.views.export_view import ExportView
from presentation.views.html_report_view import HtmlReportView

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(PROJECT_ROOT, "data", "scanners", "rules")
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "presentation", "views", "templates")
DEFAULT_GITLEAKS_BINARY = "gitleaks"
DEFAULT_SEMGREP_BINARY = "semgrep"


@dataclass(frozen=True)
class AppConfig:
    repo_path: str
    db_path: str
    gitleaks_binary: str = DEFAULT_GITLEAKS_BINARY
    semgrep_binary: str = DEFAULT_SEMGREP_BINARY


@dataclass(frozen=True)
class DependencyOverrides:
    advisory_repository: Any = None
    package_release_repository: Any = None
    secret_scanner_repository: Any = None
    pattern_scanners: Any = None
    resource_monitor: Any = None
    http_client: Any = None


@dataclass
class Controllers:
    history: HistoryController
    patch_lag: PatchLagController
    secrets: SecretsController
    patterns: PatternsController
    report: ReportController
    console_view: ConsoleView
    closeables: list = field(default_factory=list)

    def close(self):
        for closeable in self.closeables:
            closeable.close()


def pick(override, factory):
    if override is not None:
        return override
    return factory()


def build_controllers(config, overrides=None, console_view=None):
    overrides = overrides or DependencyOverrides()
    console_view = console_view or ConsoleView()
    git_repository = GitCliHistoryRepository(config.repo_path, MailmapAuthorNormalizer())
    audit_repository = SqliteAuditResultRepository(config.db_path)
    resource_monitor = pick(
        overrides.resource_monitor,
        lambda: ProcResourceMonitor(os.path.dirname(os.path.abspath(config.db_path))),
    )
    http_client = pick(overrides.http_client, UrllibJsonHttpClient)
    advisory_repository = pick(
        overrides.advisory_repository, lambda: OsvAdvisoryRepository(http_client)
    )
    release_repository = pick(
        overrides.package_release_repository,
        lambda: EcosystemReleaseRouter(
            {
                PUB_ECOSYSTEM: PubDevReleaseRepository(http_client),
                NPM_ECOSYSTEM: NpmRegistryReleaseRepository(http_client),
            }
        ),
    )
    secret_scanner = pick(
        overrides.secret_scanner_repository,
        lambda: GitleaksSecretScanner(
            config.repo_path, git_repository, binary=config.gitleaks_binary
        ),
    )
    pattern_scanners = pick(
        overrides.pattern_scanners,
        lambda: [
            SemgrepPatternScanner(RULES_DIR, binary=config.semgrep_binary),
            ConfigRulePatternScanner(),
        ],
    )
    parsers = [PubspecLockParser(), NpmLockParser(), PubspecYamlParser()]
    sync_commit_history = SyncCommitHistory(git_repository, audit_repository)
    track_finding_lifecycle = TrackFindingLifecycle(audit_repository)
    attribute_finding_to_author = AttributeFindingToAuthor(
        git_repository, audit_repository
    )
    return Controllers(
        history=HistoryController(sync_commit_history, console_view),
        patch_lag=PatchLagController(
            sync_commit_history,
            ExtractDependencyTimeline(
                git_repository, parsers, audit_repository, resource_monitor
            ),
            CalculatePatchLag(advisory_repository, release_repository, audit_repository),
            CalculateLibyears(release_repository, audit_repository),
            console_view,
        ),
        secrets=SecretsController(
            sync_commit_history,
            ScanHistoryForSecrets(secret_scanner, audit_repository),
            track_finding_lifecycle,
            attribute_finding_to_author,
            console_view,
        ),
        patterns=PatternsController(
            sync_commit_history,
            ScanHistoryForInsecurePatterns(
                git_repository, pattern_scanners, audit_repository, resource_monitor
            ),
            track_finding_lifecycle,
            attribute_finding_to_author,
            console_view,
        ),
        report=ReportController(
            BuildSecurityReport(audit_repository),
            console_view,
            HtmlReportView(TEMPLATES_DIR),
            ExportView(),
        ),
        console_view=console_view,
        closeables=[git_repository, audit_repository],
    )

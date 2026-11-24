import json
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

from domain.entities.advisory import Advisory
from domain.entities.author import Author
from domain.entities.commit import Commit, FileChange, FileChangeStatus
from domain.entities.dependency_version import DependencyVersion
from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.insecure_pattern_finding import (
    InsecurePatternFinding,
    PatternMatch,
)
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.secret_finding import SecretFinding
from domain.entities.severity import Severity
from domain.repositories.audit_result_repository import AuditResultRepository

SCHEMA = """
CREATE TABLE IF NOT EXISTS commits (
    position INTEGER NOT NULL, sha TEXT NOT NULL, author TEXT NOT NULL,
    authored_at TEXT NOT NULL, committed_at TEXT NOT NULL,
    parent_shas TEXT NOT NULL, subject TEXT NOT NULL, file_changes TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dependency_versions (
    position INTEGER NOT NULL, ecosystem TEXT NOT NULL, package TEXT NOT NULL,
    version TEXT NOT NULL, lockfile_path TEXT NOT NULL,
    start_commit_sha TEXT NOT NULL, start_at TEXT NOT NULL,
    end_commit_sha TEXT, end_at TEXT, approximated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS patch_lag_records (
    position INTEGER NOT NULL, advisory TEXT NOT NULL, lockfile_path TEXT NOT NULL,
    vulnerable_version TEXT NOT NULL, exposure_started_at TEXT NOT NULL,
    exposure_start_commit_sha TEXT NOT NULL, reference_at TEXT NOT NULL,
    fixed_version TEXT, fix_commit_sha TEXT, fixed_at TEXT, lag_days REAL,
    fixed_before_disclosure INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS libyears_points (
    position INTEGER NOT NULL, month TEXT NOT NULL, libyears REAL NOT NULL,
    package_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_findings (
    position INTEGER NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
    secret_hash TEXT NOT NULL, file_path TEXT NOT NULL, commit_sha TEXT NOT NULL,
    committed_at TEXT NOT NULL, line INTEGER NOT NULL, author TEXT NOT NULL,
    still_in_head INTEGER NOT NULL, head_line INTEGER,
    removed_commit_sha TEXT, removed_at TEXT
);
CREATE TABLE IF NOT EXISTS pattern_findings (
    position INTEGER NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
    category TEXT NOT NULL, severity TEXT NOT NULL, file_path TEXT NOT NULL,
    module TEXT NOT NULL, line INTEGER NOT NULL, commit_sha TEXT NOT NULL,
    committed_at TEXT NOT NULL, blob_sha TEXT NOT NULL, message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_lifecycles (
    position INTEGER NOT NULL, fingerprint TEXT NOT NULL, kind TEXT NOT NULL,
    rule_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
    file_path TEXT NOT NULL, module TEXT NOT NULL,
    introduced_commit_sha TEXT NOT NULL, introduced_at TEXT NOT NULL,
    fixed_commit_sha TEXT, fixed_at TEXT, last_seen_line INTEGER NOT NULL,
    introduced_by TEXT
);
CREATE TABLE IF NOT EXISTS blob_matches (
    scanner_id TEXT NOT NULL, blob_sha TEXT NOT NULL, matches TEXT NOT NULL,
    PRIMARY KEY (scanner_id, blob_sha)
);
CREATE TABLE IF NOT EXISTS run_metadata (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
"""


def encode_datetime(value):
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def decode_datetime(text):
    if text is None:
        return None
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def encode_author(author):
    if author is None:
        return None
    return json.dumps({"name": author.name, "email": author.email})


def decode_author(text):
    if text is None:
        return None
    return Author(**json.loads(text))


def encode_advisory(advisory):
    return json.dumps(
        {
            "advisory_id": advisory.advisory_id,
            "aliases": list(advisory.aliases),
            "ecosystem": advisory.ecosystem,
            "package": advisory.package,
            "summary": advisory.summary,
            "severity": advisory.severity.value,
            "published_at": encode_datetime(advisory.published_at),
            "fixed_versions": list(advisory.fixed_versions),
        }
    )


def decode_advisory(text):
    fields = json.loads(text)
    return Advisory(
        advisory_id=fields["advisory_id"],
        aliases=tuple(fields["aliases"]),
        ecosystem=fields["ecosystem"],
        package=fields["package"],
        summary=fields["summary"],
        severity=Severity(fields["severity"]),
        published_at=decode_datetime(fields["published_at"]),
        fixed_versions=tuple(fields["fixed_versions"]),
    )


def encode_file_changes(file_changes):
    return json.dumps(
        [
            {
                "path": change.path,
                "status": change.status.value,
                "old_blob_sha": change.old_blob_sha,
                "new_blob_sha": change.new_blob_sha,
            }
            for change in file_changes
        ]
    )


def decode_file_changes(text):
    return tuple(
        FileChange(
            path=item["path"],
            status=FileChangeStatus(item["status"]),
            old_blob_sha=item["old_blob_sha"],
            new_blob_sha=item["new_blob_sha"],
        )
        for item in json.loads(text)
    )


def encode_matches(matches):
    return json.dumps(
        [
            {
                "rule_id": match.rule_id,
                "category": match.category,
                "severity": match.severity.value,
                "line": match.line,
                "line_content": match.line_content,
                "message": match.message,
            }
            for match in matches
        ]
    )


def decode_matches(text):
    return [
        PatternMatch(
            rule_id=item["rule_id"],
            category=item["category"],
            severity=Severity(item["severity"]),
            line=item["line"],
            line_content=item["line_content"],
            message=item["message"],
        )
        for item in json.loads(text)
    ]


def commit_to_row(c):
    return (
        c.sha,
        encode_author(c.author),
        encode_datetime(c.authored_at),
        encode_datetime(c.committed_at),
        json.dumps(list(c.parent_shas)),
        c.subject,
        encode_file_changes(c.file_changes),
    )


def commit_from_row(r):
    return Commit(
        sha=r[0],
        author=decode_author(r[1]),
        authored_at=decode_datetime(r[2]),
        committed_at=decode_datetime(r[3]),
        parent_shas=tuple(json.loads(r[4])),
        subject=r[5],
        file_changes=decode_file_changes(r[6]),
    )


def dependency_to_row(d):
    return (
        d.ecosystem,
        d.package,
        d.version,
        d.lockfile_path,
        d.start_commit_sha,
        encode_datetime(d.start_at),
        d.end_commit_sha,
        encode_datetime(d.end_at),
        int(d.approximated),
    )


def dependency_from_row(r):
    return DependencyVersion(
        ecosystem=r[0],
        package=r[1],
        version=r[2],
        lockfile_path=r[3],
        start_commit_sha=r[4],
        start_at=decode_datetime(r[5]),
        end_commit_sha=r[6],
        end_at=decode_datetime(r[7]),
        approximated=bool(r[8]),
    )


def patch_lag_to_row(p):
    return (
        encode_advisory(p.advisory),
        p.lockfile_path,
        p.vulnerable_version,
        encode_datetime(p.exposure_started_at),
        p.exposure_start_commit_sha,
        encode_datetime(p.reference_at),
        p.fixed_version,
        p.fix_commit_sha,
        encode_datetime(p.fixed_at),
        p.lag_days,
        int(p.fixed_before_disclosure),
    )


def patch_lag_from_row(r):
    return PatchLagRecord(
        advisory=decode_advisory(r[0]),
        lockfile_path=r[1],
        vulnerable_version=r[2],
        exposure_started_at=decode_datetime(r[3]),
        exposure_start_commit_sha=r[4],
        reference_at=decode_datetime(r[5]),
        fixed_version=r[6],
        fix_commit_sha=r[7],
        fixed_at=decode_datetime(r[8]),
        lag_days=r[9],
        fixed_before_disclosure=bool(r[10]),
    )


def libyears_to_row(p):
    return (p.month.isoformat(), p.libyears, p.package_count)


def libyears_from_row(r):
    return LibyearsPoint(
        month=date.fromisoformat(r[0]), libyears=r[1], package_count=r[2]
    )


def secret_to_row(s):
    return (
        s.fingerprint,
        s.rule_id,
        s.secret_hash,
        s.file_path,
        s.commit_sha,
        encode_datetime(s.committed_at),
        s.line,
        encode_author(s.author),
        int(s.still_in_head),
        s.head_line,
        s.removed_commit_sha,
        encode_datetime(s.removed_at),
    )


def secret_from_row(r):
    return SecretFinding(
        fingerprint=r[0],
        rule_id=r[1],
        secret_hash=r[2],
        file_path=r[3],
        commit_sha=r[4],
        committed_at=decode_datetime(r[5]),
        line=r[6],
        author=decode_author(r[7]),
        still_in_head=bool(r[8]),
        head_line=r[9],
        removed_commit_sha=r[10],
        removed_at=decode_datetime(r[11]),
    )


def pattern_to_row(f):
    return (
        f.fingerprint,
        f.rule_id,
        f.category,
        f.severity.value,
        f.file_path,
        f.module,
        f.line,
        f.commit_sha,
        encode_datetime(f.committed_at),
        f.blob_sha,
        f.message,
    )


def pattern_from_row(r):
    return InsecurePatternFinding(
        fingerprint=r[0],
        rule_id=r[1],
        category=r[2],
        severity=Severity(r[3]),
        file_path=r[4],
        module=r[5],
        line=r[6],
        commit_sha=r[7],
        committed_at=decode_datetime(r[8]),
        blob_sha=r[9],
        message=r[10],
    )


def lifecycle_to_row(l):
    return (
        l.fingerprint,
        l.kind.value,
        l.rule_id,
        l.category,
        l.severity.value,
        l.file_path,
        l.module,
        l.introduced_commit_sha,
        encode_datetime(l.introduced_at),
        l.fixed_commit_sha,
        encode_datetime(l.fixed_at),
        l.last_seen_line,
        encode_author(l.introduced_by),
    )


def lifecycle_from_row(r):
    return FindingLifecycle(
        fingerprint=r[0],
        kind=FindingKind(r[1]),
        rule_id=r[2],
        category=r[3],
        severity=Severity(r[4]),
        file_path=r[5],
        module=r[6],
        introduced_commit_sha=r[7],
        introduced_at=decode_datetime(r[8]),
        fixed_commit_sha=r[9],
        fixed_at=decode_datetime(r[10]),
        last_seen_line=r[11],
        introduced_by=decode_author(r[12]),
    )


class SqliteAuditResultRepository(AuditResultRepository):
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(db_path)
        self._connection.execute("PRAGMA journal_mode=WAL")
        with self._connection:
            self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _replace_all(self, table, columns, items, to_row):
        placeholders = ", ".join("?" for _ in range(len(columns) + 1))
        names = ", ".join(("position",) + columns)
        rows = [(index,) + to_row(item) for index, item in enumerate(items)]
        with self._connection:
            self._connection.execute(f"DELETE FROM {table}")
            self._connection.executemany(
                f"INSERT INTO {table} ({names}) VALUES ({placeholders})", rows
            )

    def _load_all(self, table, columns, from_row):
        names = ", ".join(columns)
        cursor = self._connection.execute(
            f"SELECT {names} FROM {table} ORDER BY position"
        )
        return [from_row(row) for row in cursor.fetchall()]

    def save_commits(self, commits):
        self._replace_all("commits", COMMIT_COLUMNS, commits, commit_to_row)

    def load_commits(self):
        return self._load_all("commits", COMMIT_COLUMNS, commit_from_row)

    def save_dependency_versions(self, versions):
        self._replace_all(
            "dependency_versions", DEPENDENCY_COLUMNS, versions, dependency_to_row
        )

    def load_dependency_versions(self):
        return self._load_all(
            "dependency_versions", DEPENDENCY_COLUMNS, dependency_from_row
        )

    def save_patch_lag_records(self, records):
        self._replace_all(
            "patch_lag_records", PATCH_LAG_COLUMNS, records, patch_lag_to_row
        )

    def load_patch_lag_records(self):
        return self._load_all(
            "patch_lag_records", PATCH_LAG_COLUMNS, patch_lag_from_row
        )

    def save_libyears_points(self, points):
        self._replace_all(
            "libyears_points", LIBYEARS_COLUMNS, points, libyears_to_row
        )

    def load_libyears_points(self):
        return self._load_all("libyears_points", LIBYEARS_COLUMNS, libyears_from_row)

    def save_secret_findings(self, findings):
        self._replace_all("secret_findings", SECRET_COLUMNS, findings, secret_to_row)

    def load_secret_findings(self):
        return self._load_all("secret_findings", SECRET_COLUMNS, secret_from_row)

    def save_pattern_findings(self, findings):
        self._replace_all(
            "pattern_findings", PATTERN_COLUMNS, findings, pattern_to_row
        )

    def load_pattern_findings(self):
        return self._load_all("pattern_findings", PATTERN_COLUMNS, pattern_from_row)

    def save_finding_lifecycles(self, lifecycles):
        self._replace_all(
            "finding_lifecycles", LIFECYCLE_COLUMNS, lifecycles, lifecycle_to_row
        )

    def load_finding_lifecycles(self):
        return self._load_all(
            "finding_lifecycles", LIFECYCLE_COLUMNS, lifecycle_from_row
        )

    def find_blob_matches(self, scanner_id, blob_sha):
        row = self._connection.execute(
            "SELECT matches FROM blob_matches WHERE scanner_id = ? AND blob_sha = ?",
            (scanner_id, blob_sha),
        ).fetchone()
        if row is None:
            return None
        return decode_matches(row[0])

    def save_blob_matches(self, scanner_id, blob_sha, matches):
        with self._connection:
            self._connection.execute(
                "INSERT INTO blob_matches (scanner_id, blob_sha, matches) "
                "VALUES (?, ?, ?) ON CONFLICT (scanner_id, blob_sha) "
                "DO UPDATE SET matches = excluded.matches",
                (scanner_id, blob_sha, encode_matches(matches)),
            )

    def save_run_metadata(self, key, value):
        with self._connection:
            self._connection.execute(
                "INSERT INTO run_metadata (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def load_run_metadata(self, key):
        row = self._connection.execute(
            "SELECT value FROM run_metadata WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def load_run_metadata_by_prefix(self, prefix):
        escaped = (
            prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        cursor = self._connection.execute(
            "SELECT key, value FROM run_metadata WHERE key LIKE ? ESCAPE '\\'",
            (escaped + "%",),
        )
        return dict(cursor.fetchall())


COMMIT_COLUMNS = (
    "sha", "author", "authored_at", "committed_at", "parent_shas", "subject",
    "file_changes",
)
DEPENDENCY_COLUMNS = (
    "ecosystem", "package", "version", "lockfile_path", "start_commit_sha",
    "start_at", "end_commit_sha", "end_at", "approximated",
)
PATCH_LAG_COLUMNS = (
    "advisory", "lockfile_path", "vulnerable_version", "exposure_started_at",
    "exposure_start_commit_sha", "reference_at", "fixed_version",
    "fix_commit_sha", "fixed_at", "lag_days", "fixed_before_disclosure",
)
LIBYEARS_COLUMNS = ("month", "libyears", "package_count")
SECRET_COLUMNS = (
    "fingerprint", "rule_id", "secret_hash", "file_path", "commit_sha",
    "committed_at", "line", "author", "still_in_head", "head_line",
    "removed_commit_sha", "removed_at",
)
PATTERN_COLUMNS = (
    "fingerprint", "rule_id", "category", "severity", "file_path", "module",
    "line", "commit_sha", "committed_at", "blob_sha", "message",
)
LIFECYCLE_COLUMNS = (
    "fingerprint", "kind", "rule_id", "category", "severity", "file_path",
    "module", "introduced_commit_sha", "introduced_at", "fixed_commit_sha",
    "fixed_at", "last_seen_line", "introduced_by",
)

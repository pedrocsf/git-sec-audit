import hashlib
from dataclasses import dataclass
from datetime import datetime

from domain.entities.severity import Severity

FINGERPRINT_SEPARATOR = "\x00"


@dataclass(frozen=True)
class PatternMatch:
    rule_id: str
    category: str
    severity: Severity
    line: int
    line_content: str
    message: str


@dataclass(frozen=True)
class BlobToScan:
    blob_sha: str
    path: str
    content: bytes


@dataclass(frozen=True)
class InsecurePatternFinding:
    fingerprint: str
    rule_id: str
    category: str
    severity: Severity
    file_path: str
    module: str
    line: int
    commit_sha: str
    committed_at: datetime
    blob_sha: str
    message: str


def build_pattern_fingerprint(rule_id: str, file_path: str, line_content: str) -> str:
    normalized = " ".join(line_content.split())
    raw = FINGERPRINT_SEPARATOR.join((rule_id, file_path, normalized))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

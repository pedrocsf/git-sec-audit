from dataclasses import dataclass
from datetime import datetime

from domain.entities.author import Author


@dataclass(frozen=True)
class SecretFinding:
    fingerprint: str
    rule_id: str
    secret_hash: str
    file_path: str
    commit_sha: str
    committed_at: datetime
    line: int
    author: Author
    still_in_head: bool
    head_line: int | None
    removed_commit_sha: str | None
    removed_at: datetime | None

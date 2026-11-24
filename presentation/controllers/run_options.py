from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class RunOptions:
    repository_name: str
    branch: str
    first_parent: bool
    as_of: datetime
    head_revision: str
    ignore_revs_file: str | None
    output_dir: str
    include_authors: bool
    anonymize_authors: bool

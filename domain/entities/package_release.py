from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PackageRelease:
    ecosystem: str
    package: str
    version: str
    released_at: datetime

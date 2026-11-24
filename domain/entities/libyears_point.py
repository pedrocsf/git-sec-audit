from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class LibyearsPoint:
    month: date
    libyears: float
    package_count: int

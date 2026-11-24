from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @classmethod
    def from_text(cls, text: str | None) -> "Severity":
        if text is None:
            return cls.UNKNOWN
        normalized = text.strip().lower()
        if normalized == "moderate":
            return cls.MEDIUM
        for member in cls:
            if member.value == normalized:
                return member
        return cls.UNKNOWN


_RANKS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}

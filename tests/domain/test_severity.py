import pytest

from domain.entities.severity import Severity


@pytest.mark.parametrize(
    "text, expected",
    [
        ("CRITICAL", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("MODERATE", Severity.MEDIUM),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("bogus", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
    ],
)
def test_from_text(text, expected):
    assert Severity.from_text(text) is expected


def test_rank_order():
    ranks = [s.rank for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN)]
    assert ranks == [4, 3, 2, 1, 0]

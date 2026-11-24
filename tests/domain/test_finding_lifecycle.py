from datetime import datetime, timedelta, timezone

from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.severity import Severity

START = datetime(2024, 1, 1, tzinfo=timezone.utc)


def build_lifecycle(fixed_at=None):
    return FindingLifecycle(
        fingerprint="f",
        kind=FindingKind.INSECURE_PATTERN,
        rule_id="r",
        category="c",
        severity=Severity.HIGH,
        file_path="a.py",
        module="(root)",
        introduced_commit_sha="c1",
        introduced_at=START,
        fixed_commit_sha=None if fixed_at is None else "c2",
        fixed_at=fixed_at,
        last_seen_line=1,
    )


def test_open_lifetime_uses_as_of():
    lifecycle = build_lifecycle()
    assert lifecycle.is_open
    assert lifecycle.lifetime_days(START + timedelta(days=10, hours=12)) == 10.5


def test_closed_lifetime_uses_fixed_at():
    lifecycle = build_lifecycle(fixed_at=START + timedelta(days=3))
    assert not lifecycle.is_open
    assert lifecycle.lifetime_days(START + timedelta(days=100)) == 3.0

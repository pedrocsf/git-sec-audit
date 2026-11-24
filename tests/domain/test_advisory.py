from datetime import datetime, timezone

from domain.entities.advisory import Advisory
from domain.entities.severity import Severity


def build_advisory(advisory_id, aliases):
    return Advisory(
        advisory_id=advisory_id,
        aliases=aliases,
        ecosystem="npm",
        package="p",
        summary="s",
        severity=Severity.HIGH,
        published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        fixed_versions=("1.0.1",),
    )


def test_display_id_prefers_cve_alias():
    advisory = build_advisory("GHSA-1", ("GHSA-2", "CVE-2024-1", "CVE-2024-2"))
    assert advisory.display_id == "CVE-2024-1"


def test_display_id_falls_back_to_advisory_id():
    assert build_advisory("GHSA-1", ("GHSA-2",)).display_id == "GHSA-1"
    assert build_advisory("GHSA-1", ()).display_id == "GHSA-1"

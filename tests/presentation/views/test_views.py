import csv
import io
import json
import os
import re
from datetime import date, datetime, timedelta, timezone

import pytest

from domain.entities.advisory import Advisory
from domain.entities.author import Author
from domain.entities.commit import Commit
from domain.entities.dependency_version import DependencyVersion
from domain.entities.finding_lifecycle import FindingKind, FindingLifecycle
from domain.entities.insecure_pattern_finding import InsecurePatternFinding
from domain.entities.libyears_point import LibyearsPoint
from domain.entities.patch_lag_record import PatchLagRecord
from domain.entities.secret_finding import SecretFinding
from domain.entities.security_report import (
    AuthorRanking,
    PatchLagSummary,
    SecurityReport,
)
from domain.entities.severity import Severity
from presentation.views.console_view import ConsoleView
from presentation.views.export_view import ExportView
from presentation.views.html_report_view import HtmlReportView

START = datetime(2024, 1, 1, tzinfo=timezone.utc)
SHA = "a" * 40
TEMPLATES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "presentation", "views", "templates"
)
SCRIPT = "<script>alert(1)</script>"
ALICE = Author("Alice", "alice@example.com")


def day(offset):
    return START + timedelta(days=offset)


def make_record():
    advisory = Advisory(
        "GHSA-1", ("CVE-2024-1",), "npm", "left-pad", "s", Severity.CRITICAL, day(1), ("2.0.0",)
    )
    return PatchLagRecord(
        advisory, "package-lock.json", "1.0.0", day(0), SHA, day(1), "2.0.0", SHA, day(11), 10.0
    )


def make_finding(module=SCRIPT):
    return FindingLifecycle(
        "fp", FindingKind.INSECURE_PATTERN, "rule", "crypto", Severity.HIGH,
        "lib/a.py", module, SHA, day(2), None, None, 3, ALICE,
    )


def make_report(authors=True):
    rankings = (AuthorRanking("Alice", 1, 2, 0.5),) if authors else ()
    return SecurityReport(
        generated_at=day(30),
        repository_name=SCRIPT,
        patch_lag_records=(make_record(),),
        patch_lag_summaries=(PatchLagSummary(Severity.CRITICAL, 1, 0, 10.0, 10.0),),
        critical_exposure_percentage=12.5,
        libyears_curve=(
            LibyearsPoint(date(2024, 1, 1), 1.5, 3),
            LibyearsPoint(date(2024, 2, 1), 2.5, 3),
        ),
        findings=(make_finding(),),
        findings_by_category=(("crypto", 1),),
        findings_by_module=((SCRIPT, 1),),
        findings_by_month=(("2024-01", 1),),
        mean_time_to_fix_days=None,
        author_rankings=rankings,
        warnings=(SCRIPT,),
    )


def render_console(method, *args):
    stream = io.StringIO()
    getattr(ConsoleView(stream), method)(*args)
    return stream.getvalue()


def test_console_report_contains_key_fields():
    output = render_console("render_report", make_report())
    assert "CVE-2024-1" not in output
    assert "critical" in output
    assert "12.50%" in output
    assert "Alice" in output
    assert "crypto" in output


def test_console_patch_lag_short_sha_and_dates():
    output = render_console("render_patch_lag", [make_record()], [])
    assert "CVE-2024-1" in output
    assert "a" * 10 in output
    assert "a" * 11 not in output
    assert "2024-01-12" in output


def test_console_other_renderers_run():
    commit = Commit(SHA, ALICE, day(0), day(0), (), "subject")
    version = DependencyVersion("npm", "p", "1.0.0", "package-lock.json", SHA, day(0), None, None)
    secret = SecretFinding("f", "rule", "hash", "a.env", SHA, day(0), 1, ALICE, True, 1, None, None)
    pattern = InsecurePatternFinding("f", "rule", "crypto", Severity.HIGH, "a.py", "m", 1, SHA, day(0), "b", "msg")
    assert "subject" in render_console("render_commits", [commit])
    assert "1.0.0" in render_console("render_dependency_timeline", [version])
    assert "a.env" in render_console("render_secret_findings", [secret])
    assert "a.py" in render_console("render_pattern_findings", [pattern])
    assert "lib/a.py" in render_console("render_lifecycles", [make_finding()], day(10))
    assert "hello" in render_console("render_message", "hello")
    assert "AVISO" in render_console("render_warning", "w")
    assert "ERRO" in render_console("render_error", "e")


def test_html_has_svgs_escapes_and_is_self_contained(tmp_path):
    target = tmp_path / "out" / "report.html"
    path = HtmlReportView(TEMPLATES_DIR).render(make_report(), str(target))
    content = target.read_text(encoding="utf-8")
    assert path == str(target)
    assert content.count("<svg") == 5
    assert SCRIPT not in content
    assert "&lt;script&gt;" in content
    assert not re.search(r"https?://", content)
    assert "prefers-color-scheme" in content
    assert "Ranking de autores" in content


def test_html_without_authors_omits_ranking(tmp_path):
    target = tmp_path / "report.html"
    HtmlReportView(TEMPLATES_DIR).render(make_report(authors=False), str(target))
    content = target.read_text(encoding="utf-8")
    assert "Ranking de autores" not in content
    assert "Alice" not in content


def test_html_empty_report(tmp_path):
    report = SecurityReport(day(1), "r", (), (), None, (), (), (), (), (), None, (), ())
    target = tmp_path / "report.html"
    HtmlReportView(TEMPLATES_DIR).render(report, str(target))
    assert "Sem dados" in target.read_text(encoding="utf-8")


def test_json_export_is_valid(tmp_path):
    target = tmp_path / "nested" / "report.json"
    ExportView().write_json(make_report(), str(target))
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["generated_at"] == day(30).isoformat()
    assert data["patch_lag_summaries"][0]["severity"] == "critical"
    assert data["libyears_curve"][0]["month"] == "2024-01-01"


def test_csv_export_has_headers(tmp_path):
    paths = ExportView().write_csv(make_report(), str(tmp_path / "csv"))
    names = [os.path.basename(p) for p in paths]
    assert names == ["patch_lag.csv", "findings.csv", "libyears.csv"]
    for path in paths:
        with open(path, encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        assert len(rows) == 2 or path.endswith("libyears.csv")
        assert rows[0]
    with open(paths[0], encoding="utf-8", newline="") as handle:
        assert list(csv.DictReader(handle))[0]["advisory"] == "CVE-2024-1"

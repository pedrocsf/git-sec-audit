import json
from types import SimpleNamespace

import pytest

from data.scanners.semgrep_pattern_scanner import SemgrepPatternScanner
from domain.entities.insecure_pattern_finding import BlobToScan
from domain.entities.severity import Severity
from domain.errors import ScannerUnavailableError


def make_scanner(tmp_path, report=None, which=lambda name: "/bin/semgrep", returncode=0):
    (tmp_path / "rules").mkdir(exist_ok=True)
    (tmp_path / "rules" / "a.yaml").write_text("rules: []\n")
    captured = {}

    def runner(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=returncode, stdout=json.dumps(report or {"results": []}), stderr="err")

    scanner = SemgrepPatternScanner(tmp_path / "rules", runner=runner, which=which)
    return scanner, captured


def test_supports(tmp_path):
    scanner, _ = make_scanner(tmp_path)
    assert scanner.supports("lib/a.dart")
    assert scanner.supports("functions/index.ts")
    assert scanner.supports("a.cjs")
    assert not scanner.supports("a.py")


def test_scanner_id_changes_with_rules(tmp_path):
    scanner, _ = make_scanner(tmp_path)
    first = scanner.scanner_id
    assert first.startswith("semgrep:") and len(first) == len("semgrep:") + 12
    (tmp_path / "rules" / "a.yaml").write_text("rules: [1]\n")
    assert scanner.scanner_id != first


def test_missing_binary(tmp_path):
    scanner, _ = make_scanner(tmp_path, which=lambda name: None)
    with pytest.raises(ScannerUnavailableError):
        scanner.scan_blobs([BlobToScan("b", "a.js", b"x")])


def test_failure(tmp_path):
    scanner, _ = make_scanner(tmp_path, returncode=2)
    with pytest.raises(ScannerUnavailableError):
        scanner.scan_blobs([BlobToScan("b", "a.js", b"x")])


def test_maps_results(tmp_path):
    report = {
        "results": [
            {
                "check_id": "rules.dart.dart-insecure-http-url",
                "path": "/tmp/x/1.dart",
                "start": {"line": 2},
                "extra": {"message": "msg", "severity": "WARNING", "metadata": {"category": "cleartext"}},
            },
            {
                "check_id": "js-eval",
                "path": "/tmp/x/0.js",
                "start": {"line": 1},
                "extra": {"message": "m", "severity": "ERROR", "metadata": {"severity": "critical"}},
            },
        ]
    }
    scanner, captured = make_scanner(tmp_path, report)
    blobs = [
        BlobToScan("b0", "a.js", b"eval(x)\n"),
        BlobToScan("b1", "lib/a.dart", b"a\nvar u = 'http://x.com';\n"),
        BlobToScan("b2", "c.ts", b"ok\n"),
    ]
    result = scanner.scan_blobs(blobs)

    assert set(result) == {"b0", "b1", "b2"}
    assert result["b2"] == []
    dart = result["b1"][0]
    assert dart.rule_id == "dart-insecure-http-url"
    assert dart.line == 2
    assert dart.line_content == "var u = 'http://x.com';"
    assert dart.severity == Severity.MEDIUM
    assert dart.category == "cleartext"
    js = result["b0"][0]
    assert js.severity == Severity.CRITICAL
    assert js.category == "insecure-pattern"
    assert captured["command"][:2] == ["semgrep", "scan"]
    assert "--metrics=off" in captured["command"]

import pytest

from data.scanners.config_rule_pattern_scanner import ConfigRulePatternScanner
from domain.entities.insecure_pattern_finding import BlobToScan
from domain.entities.severity import Severity


def scan(path, text):
    return ConfigRulePatternScanner().scan_blobs([BlobToScan("b", path, text.encode())])["b"]


def test_scanner_id_and_supports():
    scanner = ConfigRulePatternScanner()
    assert scanner.scanner_id == "config-rules:v1"
    for path in ("firestore.rules", "x/storage.rules", "android/AndroidManifest.xml", "ios/Info.plist", "res/network_security_config.xml"):
        assert scanner.supports(path)
    assert not scanner.supports("README.md")


def test_firebase_allow_all():
    matches = scan("firestore.rules", "rules {\n  allow read, write: if true;\n}\n")
    assert [(m.rule_id, m.line, m.severity, m.category) for m in matches] == [
        ("firebase-rules-allow-all", 2, Severity.CRITICAL, "firebase-rules")
    ]


def test_firebase_negative():
    assert scan("firestore.rules", "allow read: if request.auth != null;\n") == []


@pytest.mark.parametrize("text", ['<application android:usesCleartextTraffic="true">', '<base-config cleartextTrafficPermitted="true"/>'])
def test_cleartext_positive(text):
    assert [m.rule_id for m in scan("AndroidManifest.xml", text)] == ["android-cleartext-traffic"]


def test_cleartext_negative():
    assert scan("AndroidManifest.xml", '<application android:usesCleartextTraffic="false">') == []


def test_debuggable():
    matches = scan("AndroidManifest.xml", '<application android:debuggable="true">')
    assert matches[0].rule_id == "android-debuggable" and matches[0].severity == Severity.HIGH
    assert scan("AndroidManifest.xml", '<application android:debuggable="false">') == []


def test_exported():
    matches = scan("AndroidManifest.xml", '<activity android:exported="true"/>')
    assert matches[0].rule_id == "android-exported-component" and matches[0].severity == Severity.MEDIUM
    assert scan("AndroidManifest.xml", '<activity android:exported="false"/>') == []


def test_ats_next_line_and_same_line():
    next_line = scan("Info.plist", "<key>NSAllowsArbitraryLoads</key>\n\n<true/>\n")
    assert [(m.rule_id, m.line, m.category) for m in next_line] == [("ios-ats-arbitrary-loads", 1, "ios-config")]
    same_line = scan("Info.plist", "<key>NSAllowsArbitraryLoads</key><true/>\n")
    assert len(same_line) == 1


def test_ats_negative():
    assert scan("Info.plist", "<key>NSAllowsArbitraryLoads</key>\n<false/>\n") == []

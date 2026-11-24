import re
from dataclasses import dataclass

from domain.entities.insecure_pattern_finding import BlobToScan, PatternMatch
from domain.entities.severity import Severity
from domain.repositories.pattern_scanner_repository import PatternScannerRepository

SCANNER_ID = "config-rules:v1"
FIREBASE_FILES = ("firestore.rules", "storage.rules")
ANDROID_FILES = ("AndroidManifest.xml", "network_security_config.xml")
IOS_FILES = ("Info.plist",)
SUPPORTED_FILES = FIREBASE_FILES + ANDROID_FILES + IOS_FILES
ATS_KEY = "NSAllowsArbitraryLoads"
ATS_VALUE = "<true/>"


@dataclass(frozen=True)
class LineRule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    message: str
    files: tuple[str, ...]


LINE_RULES = (
    LineRule(
        "firebase-rules-allow-all",
        "firebase-rules",
        Severity.CRITICAL,
        re.compile(r"\ballow\s+[a-z,\s]*\b(read|write|list|get|create|update|delete)\b[^:]*:\s*if\s+true\b"),
        "Security rule allows unrestricted access",
        FIREBASE_FILES,
    ),
    LineRule(
        "android-cleartext-traffic",
        "android-config",
        Severity.HIGH,
        re.compile(r"(usesCleartextTraffic|cleartextTrafficPermitted)\s*=\s*[\"']true[\"']"),
        "Cleartext HTTP traffic is permitted",
        ANDROID_FILES,
    ),
    LineRule(
        "android-debuggable",
        "android-config",
        Severity.HIGH,
        re.compile(r"android:debuggable\s*=\s*[\"']true[\"']"),
        "Application is marked debuggable",
        ANDROID_FILES,
    ),
    LineRule(
        "android-exported-component",
        "android-config",
        Severity.MEDIUM,
        re.compile(r"android:exported\s*=\s*[\"']true[\"']"),
        "Component is exported to other applications",
        ANDROID_FILES,
    ),
)

ATS_RULE = LineRule(
    "ios-ats-arbitrary-loads",
    "ios-config",
    Severity.HIGH,
    re.compile(re.escape(ATS_KEY)),
    "App Transport Security allows arbitrary loads",
    IOS_FILES,
)


class ConfigRulePatternScanner(PatternScannerRepository):
    @property
    def scanner_id(self) -> str:
        return SCANNER_ID

    def supports(self, path: str) -> bool:
        return path.rsplit("/", 1)[-1] in SUPPORTED_FILES

    def scan_blobs(self, blobs: list[BlobToScan]) -> dict[str, list[PatternMatch]]:
        return {blob.blob_sha: self._scan_blob(blob) for blob in blobs}

    def _scan_blob(self, blob: BlobToScan) -> list[PatternMatch]:
        name = blob.path.rsplit("/", 1)[-1]
        lines = blob.content.decode("utf-8", errors="replace").splitlines()
        matches = []
        for rule in LINE_RULES:
            if name in rule.files:
                matches.extend(self._match_lines(rule, lines))
        if name in ATS_RULE.files:
            matches.extend(self._match_ats(lines))
        return sorted(matches, key=lambda match: match.line)

    def _match_lines(self, rule: LineRule, lines: list[str]) -> list[PatternMatch]:
        return [
            self._build(rule, number, text)
            for number, text in enumerate(lines, start=1)
            if rule.pattern.search(text)
        ]

    def _match_ats(self, lines: list[str]) -> list[PatternMatch]:
        matches = []
        for number, text in enumerate(lines, start=1):
            if not ATS_RULE.pattern.search(text):
                continue
            if self._value_is_true(lines, number - 1):
                matches.append(self._build(ATS_RULE, number, text))
        return matches

    def _value_is_true(self, lines: list[str], key_index: int) -> bool:
        remainder = lines[key_index].split(ATS_KEY, 1)[1]
        if ATS_VALUE in remainder:
            return True
        for text in lines[key_index + 1:]:
            if not text.strip():
                continue
            return ATS_VALUE in text
        return False

    def _build(self, rule: LineRule, number: int, text: str) -> PatternMatch:
        return PatternMatch(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=rule.severity,
            line=number,
            line_content=text,
            message=rule.message,
        )

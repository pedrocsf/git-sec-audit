import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from domain.entities.insecure_pattern_finding import BlobToScan, PatternMatch
from domain.entities.severity import Severity
from domain.errors import ScannerUnavailableError
from domain.repositories.pattern_scanner_repository import PatternScannerRepository

SUPPORTED_EXTENSIONS = (".dart", ".js", ".ts", ".mjs", ".cjs")
SCANNER_PREFIX = "semgrep:"
SCANNER_HASH_LENGTH = 12
DEFAULT_CATEGORY = "insecure-pattern"
STDERR_SUMMARY_LIMIT = 200
SEMGREP_SEVERITIES = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepPatternScanner(PatternScannerRepository):
    def __init__(self, rules_dir, binary="semgrep", runner=subprocess.run, which=shutil.which):
        self._rules_dir = Path(rules_dir)
        self._binary = binary
        self._runner = runner
        self._which = which

    @property
    def scanner_id(self) -> str:
        digest = hashlib.sha256()
        for rule_file in sorted(self._rules_dir.glob("*.yaml")):
            digest.update(rule_file.read_bytes())
        return SCANNER_PREFIX + digest.hexdigest()[:SCANNER_HASH_LENGTH]

    def supports(self, path: str) -> bool:
        return path.lower().endswith(SUPPORTED_EXTENSIONS)

    def scan_blobs(self, blobs: list[BlobToScan]) -> dict[str, list[PatternMatch]]:
        if self._which(self._binary) is None:
            raise ScannerUnavailableError(f"{self._binary} não encontrado no PATH; instale para escanear padrões")
        result = {blob.blob_sha: [] for blob in blobs}
        if not blobs:
            return result
        with tempfile.TemporaryDirectory() as workdir:
            names = self._write_blobs(workdir, blobs)
            report = self._run_semgrep(workdir)
            for entry in report.get("results", []):
                index = names.get(os.path.basename(entry["path"]))
                if index is None:
                    continue
                blob = blobs[index]
                result[blob.blob_sha].append(self._to_match(entry, blob))
        return result

    def _write_blobs(self, workdir: str, blobs: list[BlobToScan]) -> dict[str, int]:
        names = {}
        for index, blob in enumerate(blobs):
            extension = os.path.splitext(blob.path)[1]
            name = f"{index}{extension}"
            Path(workdir, name).write_bytes(blob.content)
            names[name] = index
        return names

    def _run_semgrep(self, workdir: str) -> dict:
        command = [
            self._binary,
            "scan",
            "--config",
            str(self._rules_dir),
            "--json",
            "--metrics=off",
            "--quiet",
            "--disable-version-check",
            workdir,
        ]
        try:
            completed = self._runner(command, capture_output=True, text=True, check=False)
        except OSError as error:
            raise ScannerUnavailableError(f"{self._binary} falha ao executar: {type(error).__name__}") from None
        if completed.returncode != 0:
            summary = (completed.stderr or "").strip()[:STDERR_SUMMARY_LIMIT]
            raise ScannerUnavailableError(f"{self._binary} encerrou com código {completed.returncode}: {summary}")
        try:
            return json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            raise ScannerUnavailableError(f"{self._binary} produziu JSON inválido") from None

    def _to_match(self, entry: dict, blob: BlobToScan) -> PatternMatch:
        extra = entry.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        line = entry["start"]["line"]
        lines = blob.content.decode("utf-8", errors="replace").splitlines()
        line_content = lines[line - 1] if 0 < line <= len(lines) else ""
        return PatternMatch(
            rule_id=entry["check_id"].split(".")[-1],
            category=metadata.get("category") or DEFAULT_CATEGORY,
            severity=self._severity(extra.get("severity"), metadata.get("severity")),
            line=line,
            line_content=line_content,
            message=extra.get("message", ""),
        )

    def _severity(self, semgrep_severity, metadata_severity) -> Severity:
        if metadata_severity:
            return Severity.from_text(metadata_severity)
        return SEMGREP_SEVERITIES.get(semgrep_severity, Severity.UNKNOWN)

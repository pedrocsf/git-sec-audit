import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone

from domain.entities.author import Author
from domain.entities.secret_finding import SecretFinding
from domain.errors import ScannerUnavailableError
from domain.repositories.git_history_repository import GitHistoryRepository
from domain.repositories.secret_scanner_repository import SecretScannerRepository

FINGERPRINT_SEPARATOR = "\x00"
STDERR_SUMMARY_LIMIT = 200


class GitleaksSecretScanner(SecretScannerRepository):
    def __init__(
        self,
        repository_path,
        git_history_repository: GitHistoryRepository,
        binary="gitleaks",
        runner=subprocess.run,
        which=shutil.which,
    ):
        self._repository_path = str(repository_path)
        self._git_history = git_history_repository
        self._binary = binary
        self._runner = runner
        self._which = which

    def scan_history(self, branch: str) -> list[SecretFinding]:
        if self._which(self._binary) is None:
            raise ScannerUnavailableError(f"{self._binary} não encontrado no PATH; instale para escanear segredos")
        items = self._run_gitleaks(branch)
        head = self._git_history.resolve_commit(branch)
        return [self._build_finding(item, branch, head) for item in items]

    def _run_gitleaks(self, branch: str) -> list[dict]:
        command = [
            self._binary,
            "git",
            self._repository_path,
            f"--log-opts={branch}",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--exit-code",
            "0",
        ]
        try:
            completed = self._runner(command, capture_output=True, text=True, check=False)
        except OSError as error:
            raise ScannerUnavailableError(f"{self._binary} falha ao executar: {type(error).__name__}") from None
        if completed.returncode != 0:
            summary = (completed.stderr or "").strip()[:STDERR_SUMMARY_LIMIT]
            raise ScannerUnavailableError(f"{self._binary} encerrou com código {completed.returncode}: {summary}")
        output = (completed.stdout or "").strip()
        if not output:
            return []
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            raise ScannerUnavailableError(f"{self._binary} produziu JSON inválido") from None
        return parsed or []

    def _build_finding(self, item: dict, branch: str, head: str) -> SecretFinding:
        secret = item["Secret"]
        file_path = item["File"]
        secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        fingerprint = hashlib.sha256(
            FINGERPRINT_SEPARATOR.join((item["RuleID"], file_path, secret_hash)).encode("utf-8")
        ).hexdigest()
        head_content = self._git_history.read_file_at(head, file_path)
        still_in_head = head_content is not None and secret in head_content
        head_line = self._find_line(head_content, secret) if still_in_head else None
        removed_sha, removed_at = (None, None)
        if not still_in_head:
            removed_sha, removed_at = self._find_removal(branch, item["Commit"], file_path, secret)
        return SecretFinding(
            fingerprint=fingerprint,
            rule_id=item["RuleID"],
            secret_hash=secret_hash,
            file_path=file_path,
            commit_sha=item["Commit"],
            committed_at=self._parse_date(item["Date"]),
            line=item["StartLine"],
            author=Author(name=item.get("Author", ""), email=item.get("Email", "")),
            still_in_head=still_in_head,
            head_line=head_line,
            removed_commit_sha=removed_sha,
            removed_at=removed_at,
        )

    def _find_line(self, content: str, secret: str) -> int | None:
        for number, text in enumerate(content.splitlines(), start=1):
            if secret in text:
                return number
        return None

    def _find_removal(self, branch, found_sha, file_path, secret):
        commits = self._git_history.list_commits(branch, first_parent=False, paths=(file_path,))
        seen_found = False
        for commit in commits:
            if commit.sha == found_sha:
                seen_found = True
                continue
            if not seen_found:
                continue
            content = self._git_history.read_file_at(commit.sha, file_path)
            if content is None or secret not in content:
                return commit.sha, commit.committed_at
        return None, None

    def _parse_date(self, text: str) -> datetime:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

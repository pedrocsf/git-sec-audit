import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from types import TracebackType

from data.git.mailmap_author_normalizer import MailmapAuthorNormalizer
from domain.entities.author import Author
from domain.entities.commit import Commit, FileChange, FileChangeStatus
from domain.errors import GitCommandError
from domain.repositories.git_history_repository import GitHistoryRepository

RECORD_SEPARATOR = "\x1e"
FIELD_SEPARATOR = "\x1f"
COMMIT_FORMAT = "%x1e%H%x1f%P%x1f%aN%x1f%aE%x1f%aI%x1f%cI%x1f%s%x1f"
COMMIT_FIELD_COUNT = 7
STREAM_CHUNK_SIZE = 65536
ZERO_SHA_CHARACTER = "0"
BLAME_IGNORE_FILE = ".git-blame-ignore-revs"
BLAME_AUTHOR_PREFIX = "author "
BLAME_MAIL_PREFIX = "author-mail "
BLOB_MISSING_SUFFIX = " missing"
STATUS_MAP = {
    "A": FileChangeStatus.ADDED,
    "M": FileChangeStatus.MODIFIED,
    "D": FileChangeStatus.DELETED,
    "T": FileChangeStatus.TYPE_CHANGED,
    "C": FileChangeStatus.ADDED,
    "R": FileChangeStatus.MODIFIED,
    "U": FileChangeStatus.MODIFIED,
    "X": FileChangeStatus.MODIFIED,
}


class GitCliHistoryRepository(GitHistoryRepository):
    def __init__(
        self, repository_path: str, author_normalizer: MailmapAuthorNormalizer
    ) -> None:
        self._repository_path = repository_path
        self._author_normalizer = author_normalizer
        self._blob_process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "GitCliHistoryRepository":
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        process = self._blob_process
        self._blob_process = None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        process.wait()

    def list_commits(
        self, branch: str, first_parent: bool, paths: tuple[str, ...] = ()
    ) -> list[Commit]:
        arguments = [
            "log",
            branch,
            "--reverse",
            "--diff-merges=first-parent",
            "--raw",
            "--no-renames",
            "--no-abbrev",
            "-z",
            f"--format={COMMIT_FORMAT}",
        ]
        if first_parent:
            arguments.insert(3, "--first-parent")
        if paths:
            arguments.extend(["--", *paths])
        return [self._parse_record(record) for record in self._stream_records(arguments)]

    def resolve_commit(self, revision: str) -> str:
        output = self._run(["rev-parse", "--verify", f"{revision}^{{commit}}"])
        return output.decode("utf-8", errors="replace").strip()

    def read_file_at(self, commit_sha: str, path: str) -> str | None:
        completed = self._run_unchecked(["show", f"{commit_sha}:{path}"])
        if completed.returncode != 0:
            return None
        return completed.stdout.decode("utf-8", errors="replace")

    def read_blob(self, blob_sha: str) -> bytes:
        process = self._ensure_blob_process()
        assert process.stdin is not None and process.stdout is not None
        try:
            process.stdin.write(f"{blob_sha}\n".encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("utf-8", errors="replace").strip()
            if not header or header.endswith(BLOB_MISSING_SUFFIX):
                raise GitCommandError(f"Blob not found: {blob_sha}")
            size = int(header.split()[2])
            content = self._read_exact(process.stdout, size)
            process.stdout.read(1)
        except (OSError, ValueError, IndexError) as error:
            self.close()
            raise GitCommandError(f"Failed to read blob {blob_sha}: {error}") from error
        return content

    def find_paths_in_history(
        self, branch: str, file_names: tuple[str, ...]
    ) -> list[str]:
        if not file_names:
            return []
        pathspecs = [f":(glob)**/{name}" for name in file_names]
        output = self._run(
            [
                "log",
                branch,
                "--format=",
                "--name-only",
                "--no-renames",
                "-z",
                "--",
                *pathspecs,
            ]
        )
        names = set(file_names)
        found = {
            path
            for path in output.decode("utf-8", errors="replace").split("\0")
            if path.strip() and path.rsplit("/", 1)[-1] in names
        }
        return sorted(found)

    def blame_line(
        self, commit_sha: str, path: str, line: int, ignore_revs_file: str | None
    ) -> tuple[str, Author] | None:
        arguments = ["blame", "-w", "-M", "-C", "--porcelain", "-L", f"{line},{line}"]
        ignore_file = self._resolve_ignore_revs_file(ignore_revs_file)
        if ignore_file is not None:
            arguments.extend(["--ignore-revs-file", ignore_file])
        arguments.extend([commit_sha, "--", path])
        completed = self._run_unchecked(arguments)
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")
            if "no such line" in stderr or "has only" in stderr:
                return None
            raise GitCommandError(f"git blame failed: {stderr.strip()}")
        return self._parse_blame(completed.stdout.decode("utf-8", errors="replace"))

    def _resolve_ignore_revs_file(self, ignore_revs_file: str | None) -> str | None:
        if ignore_revs_file is not None:
            return ignore_revs_file
        default_path = os.path.join(self._repository_path, BLAME_IGNORE_FILE)
        if os.path.isfile(default_path):
            return default_path
        return None

    def _parse_blame(self, output: str) -> tuple[str, Author] | None:
        lines = output.splitlines()
        if not lines:
            return None
        commit_sha = lines[0].split()[0]
        name = ""
        email = ""
        for line in lines[1:]:
            if line.startswith(BLAME_AUTHOR_PREFIX):
                name = line[len(BLAME_AUTHOR_PREFIX):]
            elif line.startswith(BLAME_MAIL_PREFIX):
                email = line[len(BLAME_MAIL_PREFIX):].strip("<>")
        author = self._author_normalizer.normalize(Author(name=name, email=email))
        return commit_sha, author

    def _ensure_blob_process(self) -> subprocess.Popen[bytes]:
        if self._blob_process is not None and self._blob_process.poll() is None:
            return self._blob_process
        try:
            self._blob_process = subprocess.Popen(
                ["git", "-C", self._repository_path, "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise GitCommandError(f"Unable to start git: {error}") from error
        return self._blob_process

    @staticmethod
    def _read_exact(stream, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining > 0:
            chunk = stream.read(remaining)
            if not chunk:
                raise OSError("unexpected end of git cat-file output")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _run_unchecked(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                ["git", "-C", self._repository_path, *arguments],
                capture_output=True,
                check=False,
            )
        except OSError as error:
            raise GitCommandError(f"Unable to start git: {error}") from error

    def _run(self, arguments: list[str]) -> bytes:
        completed = self._run_unchecked(arguments)
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise GitCommandError(f"git {arguments[0]} failed: {stderr}")
        return completed.stdout

    def _stream_records(self, arguments: list[str]) -> Iterator[str]:
        try:
            process = subprocess.Popen(
                ["git", "-C", self._repository_path, *arguments],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise GitCommandError(f"Unable to start git: {error}") from error
        assert process.stdout is not None and process.stderr is not None
        buffer = b""
        separator = RECORD_SEPARATOR.encode("utf-8")
        try:
            while True:
                chunk = process.stdout.read(STREAM_CHUNK_SIZE)
                if not chunk:
                    break
                buffer += chunk
                *complete, buffer = buffer.split(separator)
                for record in complete:
                    if record:
                        yield record.decode("utf-8", errors="replace")
            if buffer:
                yield buffer.decode("utf-8", errors="replace")
            stderr = process.stderr.read()
            if process.wait() != 0:
                raise GitCommandError(
                    f"git {arguments[0]} failed: "
                    f"{stderr.decode('utf-8', errors='replace').strip()}"
                )
        finally:
            process.stdout.close()
            process.stderr.close()
            if process.poll() is None:
                process.kill()
                process.wait()

    def _parse_record(self, record: str) -> Commit:
        fields = record.split(FIELD_SEPARATOR, COMMIT_FIELD_COUNT)
        if len(fields) != COMMIT_FIELD_COUNT + 1:
            raise GitCommandError(f"Unexpected git log output: {record[:80]!r}")
        sha, parents, name, email, authored, committed, subject, raw = fields
        author = self._author_normalizer.normalize(Author(name=name, email=email))
        return Commit(
            sha=sha,
            author=author,
            authored_at=_to_utc(authored),
            committed_at=_to_utc(committed),
            parent_shas=tuple(parents.split()),
            subject=subject,
            file_changes=self._parse_file_changes(raw),
        )

    @staticmethod
    def _parse_file_changes(raw: str) -> tuple[FileChange, ...]:
        tokens = [token for token in raw.split("\0")]
        changes = []
        index = 0
        while index < len(tokens):
            token = tokens[index].lstrip("\n")
            if not token.startswith(":"):
                index += 1
                continue
            metadata = token.split()
            if len(metadata) < 5 or index + 1 >= len(tokens):
                raise GitCommandError(f"Unexpected raw diff entry: {token!r}")
            old_sha, new_sha, status = metadata[2], metadata[3], metadata[4][0]
            changes.append(
                FileChange(
                    path=tokens[index + 1],
                    status=STATUS_MAP.get(status, FileChangeStatus.MODIFIED),
                    old_blob_sha=_blob_or_none(old_sha),
                    new_blob_sha=_blob_or_none(new_sha),
                )
            )
            index += 2
        return tuple(changes)


def _blob_or_none(sha: str) -> str | None:
    if set(sha) == {ZERO_SHA_CHARACTER}:
        return None
    return sha


def _to_utc(iso_text: str) -> datetime:
    return datetime.fromisoformat(iso_text).astimezone(UTC)

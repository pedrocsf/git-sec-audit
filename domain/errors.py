class GitSecAuditError(Exception):
    pass


class ScannerUnavailableError(GitSecAuditError):
    pass


class InsufficientResourcesError(GitSecAuditError):
    pass


class ExternalServiceError(GitSecAuditError):
    pass


class GitCommandError(GitSecAuditError):
    pass


class LockfileParseError(GitSecAuditError):
    pass

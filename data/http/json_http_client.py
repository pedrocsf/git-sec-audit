import json
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable

from domain.errors import ExternalServiceError

USER_AGENT = "git-sec-audit"
JSON_CONTENT_TYPE = "application/json"
NOT_FOUND_STATUS = 404
TOO_MANY_REQUESTS_STATUS = 429
SERVER_ERROR_MIN_STATUS = 500
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_FACTOR = 2


class JsonHttpClient(ABC):
    @abstractmethod
    def get_json(self, url: str) -> Any | None:
        ...

    @abstractmethod
    def post_json(self, url: str, payload: Any) -> Any:
        ...


class UrllibJsonHttpClient(JsonHttpClient):
    def __init__(
        self,
        timeout_seconds: float = 30,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._sleep = sleep

    def get_json(self, url: str) -> Any | None:
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": JSON_CONTENT_TYPE}
        )
        return self._send(request, url, allow_not_found=True)

    def post_json(self, url: str, payload: Any) -> Any:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"User-Agent": USER_AGENT, "Content-Type": JSON_CONTENT_TYPE},
            method="POST",
        )
        return self._send(request, url, allow_not_found=False)

    def _send(
        self, request: urllib.request.Request, url: str, allow_not_found: bool
    ) -> Any | None:
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                self._sleep(BACKOFF_BASE_SECONDS * BACKOFF_FACTOR ** (attempt - 1))
            try:
                return self._read(request)
            except urllib.error.HTTPError as error:
                if error.code == NOT_FOUND_STATUS and allow_not_found:
                    return None
                if not self._is_retryable_status(error.code):
                    raise ExternalServiceError(
                        f"HTTP {error.code} from {url}"
                    ) from error
                last_error = error
            except urllib.error.URLError as error:
                last_error = error
            except (TimeoutError, json.JSONDecodeError) as error:
                raise ExternalServiceError(f"Invalid response from {url}") from error
        raise ExternalServiceError(
            f"Request to {url} failed after retries: {last_error}"
        ) from last_error

    def _read(self, request: urllib.request.Request) -> Any:
        with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _is_retryable_status(status: int) -> bool:
        return status == TOO_MANY_REQUESTS_STATUS or status >= SERVER_ERROR_MIN_STATUS

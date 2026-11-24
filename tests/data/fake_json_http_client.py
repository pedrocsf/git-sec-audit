from typing import Any

from data.http.json_http_client import JsonHttpClient


class FakeJsonHttpClient(JsonHttpClient):
    def __init__(self, get_responses=None, post_handler=None) -> None:
        self.get_responses: dict[str, Any] = get_responses or {}
        self.post_handler = post_handler
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, Any]] = []

    def get_json(self, url: str) -> Any | None:
        self.get_calls.append(url)
        return self.get_responses.get(url)

    def post_json(self, url: str, payload: Any) -> Any:
        self.post_calls.append((url, payload))
        return self.post_handler(url, payload)

import io
import json
import urllib.error

import pytest

from data.http.json_http_client import UrllibJsonHttpClient
from domain.errors import ExternalServiceError


class FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def http_error(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(b""))


def install(monkeypatch, outcomes):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


def test_get_returns_json_with_headers(monkeypatch):
    calls = install(monkeypatch, [{"a": 1}])
    assert UrllibJsonHttpClient().get_json("http://x") == {"a": 1}
    assert calls[0].get_header("User-agent") == "git-sec-audit"


def test_get_returns_none_on_404(monkeypatch):
    install(monkeypatch, [http_error(404)])
    assert UrllibJsonHttpClient().get_json("http://x") is None


def test_post_sends_payload_and_content_type(monkeypatch):
    calls = install(monkeypatch, [{"ok": True}])
    assert UrllibJsonHttpClient().post_json("http://x", {"k": "v"}) == {"ok": True}
    assert calls[0].get_header("Content-type") == "application/json"
    assert json.loads(calls[0].data) == {"k": "v"}


def test_retries_with_exponential_backoff(monkeypatch):
    install(monkeypatch, [http_error(429), http_error(503), {"ok": 1}])
    sleeps = []
    client = UrllibJsonHttpClient(sleep=sleeps.append)
    assert client.get_json("http://x") == {"ok": 1}
    assert sleeps == [1.0, 2.0]


def test_retries_on_url_error(monkeypatch):
    install(monkeypatch, [urllib.error.URLError("down"), {"ok": 1}])
    assert UrllibJsonHttpClient(sleep=lambda s: None).get_json("http://x") == {"ok": 1}


def test_exhausted_retries_raise(monkeypatch):
    install(monkeypatch, [http_error(500)] * 4)
    with pytest.raises(ExternalServiceError):
        UrllibJsonHttpClient(sleep=lambda s: None).get_json("http://x")


def test_client_error_raises_without_retry(monkeypatch):
    calls = install(monkeypatch, [http_error(400), {"ok": 1}])
    with pytest.raises(ExternalServiceError):
        UrllibJsonHttpClient(sleep=lambda s: None).get_json("http://x")
    assert len(calls) == 1


def test_404_on_post_raises(monkeypatch):
    install(monkeypatch, [http_error(404)])
    with pytest.raises(ExternalServiceError):
        UrllibJsonHttpClient().post_json("http://x", {})

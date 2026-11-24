from datetime import datetime, timezone
from typing import Any

from data.http.json_http_client import JsonHttpClient
from domain.entities.advisory import Advisory
from domain.entities.severity import Severity
from domain.repositories.advisory_repository import AdvisoryRepository

DEFAULT_BASE_URL = "https://api.osv.dev"
BATCH_SIZE = 1000
SUMMARY_MAX_LENGTH = 200
CRITICAL_SCORE = 9.0
HIGH_SCORE = 7.0
MEDIUM_SCORE = 4.0

Query = tuple[str, str, str]


class OsvAdvisoryRepository(AdvisoryRepository):
    def __init__(
        self, http_client: JsonHttpClient, base_url: str = DEFAULT_BASE_URL
    ) -> None:
        self._http_client = http_client
        self._base_url = base_url.rstrip("/")
        self._ids_by_query: dict[Query, tuple[str, ...]] = {}
        self._vulns_by_id: dict[str, dict[str, Any]] = {}

    def prefetch(self, queries: list[Query]) -> None:
        pending = [q for q in dict.fromkeys(queries) if q not in self._ids_by_query]
        for start in range(0, len(pending), BATCH_SIZE):
            self._prefetch_batch(pending[start : start + BATCH_SIZE])

    def find_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> list[Advisory]:
        query = (ecosystem, package, version)
        if query not in self._ids_by_query:
            self._ids_by_query[query] = self._query_single(query)
        advisories = []
        for vuln_id in self._ids_by_query[query]:
            vuln = self._load_vuln(vuln_id)
            if vuln is not None:
                advisories.append(self._to_advisory(vuln, ecosystem, package))
        return advisories

    def _prefetch_batch(self, batch: list[Query]) -> None:
        ids_by_index: dict[int, list[str]] = {i: [] for i in range(len(batch))}
        page_tokens: dict[int, str] = {}
        active = list(range(len(batch)))
        while active:
            payload = {
                "queries": [self._build_query(batch[i], page_tokens.get(i)) for i in active]
            }
            response = self._http_client.post_json(
                f"{self._base_url}/v1/querybatch", payload
            )
            results = response.get("results", [])
            next_active = []
            for position, index in enumerate(active):
                result = results[position] if position < len(results) else {}
                ids_by_index[index].extend(v["id"] for v in result.get("vulns", []))
                token = result.get("next_page_token")
                if token:
                    page_tokens[index] = token
                    next_active.append(index)
            active = next_active
        for index, query in enumerate(batch):
            self._ids_by_query[query] = tuple(dict.fromkeys(ids_by_index[index]))
        for index in range(len(batch)):
            for vuln_id in ids_by_index[index]:
                self._load_vuln(vuln_id)

    def _query_single(self, query: Query) -> tuple[str, ...]:
        ids: list[str] = []
        page_token = None
        while True:
            response = self._http_client.post_json(
                f"{self._base_url}/v1/query", self._build_query(query, page_token)
            )
            ids.extend(v["id"] for v in response.get("vulns", []))
            page_token = response.get("next_page_token")
            if not page_token:
                return tuple(dict.fromkeys(ids))

    @staticmethod
    def _build_query(query: Query, page_token: str | None) -> dict[str, Any]:
        ecosystem, package, version = query
        built: dict[str, Any] = {
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }
        if page_token:
            built["page_token"] = page_token
        return built

    def _load_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        if vuln_id not in self._vulns_by_id:
            vuln = self._http_client.get_json(f"{self._base_url}/v1/vulns/{vuln_id}")
            if vuln is None:
                return None
            self._vulns_by_id[vuln_id] = vuln
        return self._vulns_by_id[vuln_id]

    def _to_advisory(self, vuln: dict[str, Any], ecosystem: str, package: str) -> Advisory:
        return Advisory(
            advisory_id=vuln["id"],
            aliases=tuple(vuln.get("aliases", [])),
            ecosystem=ecosystem,
            package=package,
            summary=self._summary(vuln),
            severity=self._severity(vuln),
            published_at=self._published_at(vuln),
            fixed_versions=self._fixed_versions(vuln, ecosystem, package),
        )

    @staticmethod
    def _summary(vuln: dict[str, Any]) -> str:
        return vuln.get("summary") or (vuln.get("details") or "")[:SUMMARY_MAX_LENGTH]

    @staticmethod
    def _published_at(vuln: dict[str, Any]) -> datetime:
        text = vuln.get("published")
        if not text:
            return datetime.min.replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _severity(self, vuln: dict[str, Any]) -> Severity:
        database = Severity.from_text(
            (vuln.get("database_specific") or {}).get("severity")
        )
        if database != Severity.UNKNOWN:
            return database
        for affected in vuln.get("affected", []):
            specific = Severity.from_text(
                (affected.get("ecosystem_specific") or {}).get("severity")
            )
            if specific != Severity.UNKNOWN:
                return specific
        return self._severity_from_scores(vuln.get("severity", []))

    @staticmethod
    def _severity_from_scores(entries: list[dict[str, Any]]) -> Severity:
        for entry in entries:
            try:
                score = float(entry.get("score"))
            except (TypeError, ValueError):
                continue
            if score >= CRITICAL_SCORE:
                return Severity.CRITICAL
            if score >= HIGH_SCORE:
                return Severity.HIGH
            if score >= MEDIUM_SCORE:
                return Severity.MEDIUM
            if score > 0:
                return Severity.LOW
        return Severity.UNKNOWN

    @staticmethod
    def _fixed_versions(
        vuln: dict[str, Any], ecosystem: str, package: str
    ) -> tuple[str, ...]:
        fixed: list[str] = []
        for affected in vuln.get("affected", []):
            target = affected.get("package") or {}
            if target.get("name") != package or target.get("ecosystem") != ecosystem:
                continue
            for range_entry in affected.get("ranges", []):
                for event in range_entry.get("events", []):
                    if "fixed" in event and event["fixed"] not in fixed:
                        fixed.append(event["fixed"])
        return tuple(fixed)

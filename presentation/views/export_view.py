import csv
import json
import os
from dataclasses import fields, is_dataclass
from datetime import date, datetime
from enum import Enum

JSON_INDENT = 2
PATCH_LAG_FILE = "patch_lag.csv"
FINDINGS_FILE = "findings.csv"
LIBYEARS_FILE = "libyears.csv"
EMPTY_CELL = ""
PATCH_LAG_HEADER = (
    "advisory", "package", "ecosystem", "severity", "lockfile_path",
    "vulnerable_version", "fixed_version", "exposure_started_at",
    "reference_at", "fixed_at", "lag_days", "fix_commit_sha", "is_open",
    "fixed_before_disclosure",
)
FINDINGS_HEADER = (
    "kind", "rule_id", "category", "severity", "file_path", "module",
    "introduced_commit_sha", "introduced_at", "fixed_commit_sha", "fixed_at",
    "last_seen_line", "is_open", "introduced_by",
)
LIBYEARS_HEADER = ("month", "libyears", "package_count")


def to_serializable(value):
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_serializable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (tuple, list)):
        return [to_serializable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_serializable(item) for key, item in value.items()}
    return value


def cell(value):
    if value is None:
        return EMPTY_CELL
    return to_serializable(value)


class ExportView:
    def write_json(self, report, path):
        self._ensure_parent(path)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self._serialize_report(report), handle, indent=JSON_INDENT, ensure_ascii=False)
        return path

    def _serialize_report(self, report):
        data = to_serializable(report)
        visible = self._visible_names(report)
        for finding in data["findings"]:
            author = finding["introduced_by"]
            if author is not None and author["name"] not in visible:
                finding["introduced_by"] = None
        return data

    def _visible_names(self, report):
        return {ranking.author_label for ranking in report.author_rankings}

    def write_csv(self, report, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        targets = (
            (PATCH_LAG_FILE, PATCH_LAG_HEADER, self._patch_lag_rows(report)),
            (FINDINGS_FILE, FINDINGS_HEADER, self._finding_rows(report)),
            (LIBYEARS_FILE, LIBYEARS_HEADER, self._libyears_rows(report)),
        )
        return [self._write_table(output_dir, name, header, rows) for name, header, rows in targets]

    def _write_table(self, output_dir, name, header, rows):
        path = os.path.join(output_dir, name)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def _patch_lag_rows(self, report):
        return [
            [
                cell(r.advisory.display_id), cell(r.advisory.package),
                cell(r.advisory.ecosystem), cell(r.severity),
                cell(r.lockfile_path), cell(r.vulnerable_version),
                cell(r.fixed_version), cell(r.exposure_started_at),
                cell(r.reference_at), cell(r.fixed_at), cell(r.lag_days),
                cell(r.fix_commit_sha), cell(r.is_open),
                cell(r.fixed_before_disclosure),
            ]
            for r in report.patch_lag_records
        ]

    def _finding_rows(self, report):
        visible = self._visible_names(report)
        return [
            [
                cell(f.kind), cell(f.rule_id), cell(f.category), cell(f.severity),
                cell(f.file_path), cell(f.module), cell(f.introduced_commit_sha),
                cell(f.introduced_at), cell(f.fixed_commit_sha), cell(f.fixed_at),
                cell(f.last_seen_line), cell(f.is_open),
                cell(f.introduced_by.name if f.introduced_by and f.introduced_by.name in visible else None),
            ]
            for f in report.findings
        ]

    def _libyears_rows(self, report):
        return [
            [cell(p.month), cell(p.libyears), cell(p.package_count)]
            for p in report.libyears_curve
        ]

    def _ensure_parent(self, path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

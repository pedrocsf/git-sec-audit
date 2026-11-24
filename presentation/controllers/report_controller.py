import os

from domain.use_cases.build_security_report import BuildSecurityReportRequest

HTML_FILE_NAME = "report.html"
JSON_FILE_NAME = "report.json"


class ReportController:
    def __init__(self, build_security_report, console_view, html_report_view, export_view):
        self._build_security_report = build_security_report
        self._console_view = console_view
        self._html_report_view = html_report_view
        self._export_view = export_view

    def run(self, output_dir, as_of, include_authors, anonymize_authors):
        report = self._build_security_report.execute(
            BuildSecurityReportRequest(as_of, include_authors, anonymize_authors)
        )
        self._console_view.render_report(report)
        os.makedirs(output_dir, exist_ok=True)
        html_path = self._html_report_view.render(
            report, os.path.join(output_dir, HTML_FILE_NAME)
        )
        json_path = os.path.join(output_dir, JSON_FILE_NAME)
        self._export_view.write_json(report, json_path)
        csv_paths = self._export_view.write_csv(report, output_dir)
        for generated_path in [html_path, json_path, *csv_paths]:
            self._console_view.render_message(generated_path)

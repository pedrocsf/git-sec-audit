import sys

DATE_FORMAT = "%Y-%m-%d"
SHORT_SHA_LENGTH = 10
COLUMN_SEPARATOR = "  "
EMPTY_CELL = "-"
OPEN_LABEL = "aberto"
CLOSED_LABEL = "fechado"
ERROR_PREFIX = "ERRO: "
WARNING_PREFIX = "AVISO: "
LAG_DECIMALS = 1


def short_sha(sha):
    if sha is None:
        return EMPTY_CELL
    return sha[:SHORT_SHA_LENGTH]


def format_date(moment):
    if moment is None:
        return EMPTY_CELL
    return moment.strftime(DATE_FORMAT)


def format_number(value):
    if value is None:
        return EMPTY_CELL
    return f"{value:.{LAG_DECIMALS}f}"


def format_percentage(value):
    if value is None:
        return EMPTY_CELL
    return f"{value:.2f}%"


class ConsoleView:
    def __init__(self, stream=sys.stdout):
        self._stream = stream

    def render_commits(self, commits):
        self._title(f"Commits ({len(commits)})")
        rows = [
            (short_sha(c.sha), format_date(c.committed_at), c.author.name, c.subject)
            for c in commits
        ]
        self._table(("sha", "data", "autor", "assunto"), rows)

    def render_dependency_timeline(self, versions):
        self._title(f"Linha do tempo de dependências ({len(versions)})")
        rows = [
            (
                v.ecosystem,
                v.package,
                v.version,
                v.lockfile_path,
                format_date(v.start_at),
                format_date(v.end_at),
                "sim" if v.approximated else "não",
            )
            for v in versions
        ]
        headers = ("ecossistema", "pacote", "versão", "lockfile", "início", "fim", "aprox.")
        self._table(headers, rows)

    def render_patch_lag(self, records, libyears_points):
        self._title(f"Patch lag ({len(records)})")
        rows = [
            (
                r.advisory.display_id,
                r.advisory.package,
                r.severity.value,
                r.vulnerable_version,
                r.fixed_version or EMPTY_CELL,
                format_date(r.exposure_started_at),
                format_date(r.fixed_at),
                format_number(r.lag_days),
                short_sha(r.fix_commit_sha),
            )
            for r in records
        ]
        headers = (
            "advisory", "pacote", "severidade", "vulnerável", "corrigida",
            "exposta_em", "corrigido_em", "lag_dias", "commit_correção",
        )
        self._table(headers, rows)
        self._title(f"Libyears ({len(libyears_points)})")
        point_rows = [
            (p.month.strftime(DATE_FORMAT), f"{p.libyears:.2f}", str(p.package_count))
            for p in libyears_points
        ]
        self._table(("mês", "libyears", "pacotes"), point_rows)

    def render_secret_findings(self, findings):
        self._title(f"Segredos ({len(findings)})")
        rows = [
            (
                f.rule_id,
                f.file_path,
                str(f.line),
                short_sha(f.commit_sha),
                format_date(f.committed_at),
                f.author.name,
                "sim" if f.still_in_head else "não",
                format_date(f.removed_at),
            )
            for f in findings
        ]
        headers = ("regra", "arquivo", "linha", "commit", "data", "autor", "no_head", "removido")
        self._table(headers, rows)

    def render_pattern_findings(self, findings):
        self._title(f"Padrões inseguros ({len(findings)})")
        rows = [
            (
                f.rule_id,
                f.category,
                f.severity.value,
                f.file_path,
                str(f.line),
                short_sha(f.commit_sha),
                format_date(f.committed_at),
            )
            for f in findings
        ]
        headers = ("regra", "categoria", "severidade", "arquivo", "linha", "commit", "data")
        self._table(headers, rows)

    def render_lifecycles(self, lifecycles, as_of):
        self._title(f"Ciclos de vida dos achados ({len(lifecycles)})")
        rows = [
            (
                f.kind.value,
                f.rule_id,
                f.category,
                f.severity.value,
                f.file_path,
                OPEN_LABEL if f.is_open else CLOSED_LABEL,
                format_date(f.introduced_at),
                format_date(f.fixed_at),
                format_number(f.lifetime_days(as_of)),
            )
            for f in lifecycles
        ]
        headers = ("tipo", "regra", "categoria", "severidade", "arquivo", "estado", "introduzido", "corrigido", "dias")
        self._table(headers, rows)

    def render_report(self, report):
        self._title(f"Relatório de segurança: {report.repository_name}")
        self._line(f"Gerado em: {format_date(report.generated_at)}")
        self._line(f"Exposição crítica: {format_percentage(report.critical_exposure_percentage)}")
        self._line(f"Tempo médio de correção (dias): {format_number(report.mean_time_to_fix_days)}")
        self._title("Patch lag por severidade")
        summary_rows = [
            (
                s.severity.value,
                str(s.total),
                str(s.open_count),
                format_number(s.median_lag_days),
                format_number(s.p90_lag_days),
            )
            for s in report.patch_lag_summaries
        ]
        self._table(("severidade", "total", "abertos", "mediana", "p90"), summary_rows)
        self._counts("Achados por categoria", "categoria", report.findings_by_category)
        self._counts("Achados por módulo", "módulo", report.findings_by_module)
        self._counts("Achados por mês", "mês", report.findings_by_month)
        self._title("Libyears")
        point_rows = [
            (p.month.strftime(DATE_FORMAT), f"{p.libyears:.2f}", str(p.package_count))
            for p in report.libyears_curve
        ]
        self._table(("mês", "libyears", "pacotes"), point_rows)
        if report.author_rankings:
            self._title("Ranking de autores")
            ranking_rows = [
                (
                    a.author_label,
                    str(a.finding_count),
                    str(a.commit_count),
                    f"{a.findings_per_commit:.4f}",
                )
                for a in report.author_rankings
            ]
            self._table(("autor", "achados", "commits", "por_commit"), ranking_rows)
        for warning in report.warnings:
            self.render_warning(warning)

    def render_message(self, text):
        self._line(text)

    def render_warning(self, text):
        self._line(f"{WARNING_PREFIX}{text}")

    def render_error(self, text):
        self._line(f"{ERROR_PREFIX}{text}")

    def _counts(self, title, header, pairs):
        self._title(title)
        self._table((header, "quantidade"), [(name, str(count)) for name, count in pairs])

    def _title(self, text):
        self._line("")
        self._line(text)

    def _line(self, text):
        self._stream.write(text + "\n")

    def _table(self, headers, rows):
        if not rows:
            self._line("(nenhum)")
            return
        widths = [
            max(len(str(headers[i])), *(len(str(row[i])) for row in rows))
            for i in range(len(headers))
        ]
        self._line(self._format_row(headers, widths))
        self._line(self._format_row(["-" * width for width in widths], widths))
        for row in rows:
            self._line(self._format_row(row, widths))

    def _format_row(self, cells, widths):
        padded = [str(cell).ljust(width) for cell, width in zip(cells, widths)]
        return COLUMN_SEPARATOR.join(padded).rstrip()
